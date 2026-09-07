/* SPDX-License-Identifier: Apache-2.0 */
#include <string.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/kernel.h>
#include "babblekit/testcase.h"
#include "babblekit/sync.h"
#include "host/smp.h"

void test_spake_crypto(void);

static const struct scenario {
	const char *name;
	uint32_t a, b;
	uint16_t delay_a, delay_b;
	enum bt_spake_test_fault fault;
	enum bt_security_err error;
} cases[] = {
	{"matching", 123456, 123456, 0, 0, BT_SPAKE_TEST_NONE, BT_SECURITY_ERR_SUCCESS},
	{"mismatch", 123456, 123457, 0, 0, BT_SPAKE_TEST_NONE, BT_SECURITY_ERR_AUTH_FAIL},
	{"recovery", 123456, 123456, 0, 0, BT_SPAKE_TEST_NONE, BT_SECURITY_ERR_SUCCESS},
	{"delayed-B", 123456, 123456, 0, 300, BT_SPAKE_TEST_NONE, BT_SECURITY_ERR_SUCCESS},
	{"delayed-A", 123456, 123456, 300, 0, BT_SPAKE_TEST_NONE, BT_SECURITY_ERR_SUCCESS},
	{"zero", 0, 0, 0, 0, BT_SPAKE_TEST_NONE, BT_SECURITY_ERR_SUCCESS},
	{"invalid-point", 123456, 123456, 0, 0, BT_SPAKE_TEST_INVALID_POINT,
	 BT_SECURITY_ERR_INVALID_PARAM},
	{"duplicate-point", 123456, 123456, 0, 0, BT_SPAKE_TEST_DUPLICATE_POINT,
	 BT_SECURITY_ERR_UNSPECIFIED},
};

static struct bt_conn *connection;
static bool is_central, complete, failed;
static bt_security_t reached_level;
static enum bt_security_err failure_reason;
static size_t scenario_index;
static atomic_t keypress_received;
static uint16_t value_handle;
static uint8_t payload[8], stored[8];
static size_t stored_len;
static K_SEM_DEFINE(connected_sem, 0, 1);
static K_SEM_DEFINE(disconnected_sem, 0, 1);
static K_SEM_DEFINE(pair_sem, 0, 1);
static K_SEM_DEFINE(encrypted_sem, 0, 1);
static K_SEM_DEFINE(io_sem, 0, 1);
static K_SEM_DEFINE(written_sem, 0, 1);

static void wait_event(struct k_sem *sem, const char *name)
{
	TEST_ASSERT(k_sem_take(sem, K_SECONDS(10)) == 0, "%s: timed out waiting for %s",
		    cases[scenario_index].name, name);
}

static void barrier(void)
{
	bk_sync_send();
	bk_sync_wait();
}

static ssize_t read_value(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			 void *buf, uint16_t len, uint16_t offset)
{
	return bt_gatt_attr_read(conn, attr, buf, len, offset, stored, stored_len);
}

static ssize_t write_value(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			  const void *buf, uint16_t len, uint16_t offset, uint8_t flags)
{
	ARG_UNUSED(attr);
	ARG_UNUSED(flags);
	TEST_ASSERT(bt_conn_get_security(conn) == BT_SECURITY_L4, "Unencrypted GATT write");
	if (offset || len != sizeof(stored)) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}
	memcpy(stored, buf, len);
	stored_len = len;
	k_sem_give(&written_sem);
	return len;
}

#define SERVICE_UUID BT_UUID_DECLARE_128(BT_UUID_128_ENCODE(0xf0b10000, 0x7341, 0x4528, \
							  0x9ab1, 0x010203040506))
#define VALUE_UUID BT_UUID_DECLARE_128(BT_UUID_128_ENCODE(0xf0b10001, 0x7341, 0x4528, \
							0x9ab1, 0x010203040506))

BT_GATT_SERVICE_DEFINE(test_service,
	BT_GATT_PRIMARY_SERVICE(SERVICE_UUID),
	BT_GATT_CHARACTERISTIC(VALUE_UUID, BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE,
		BT_GATT_PERM_READ_ENCRYPT | BT_GATT_PERM_WRITE_ENCRYPT,
		read_value, write_value, NULL));

static void connected(struct bt_conn *conn, uint8_t err)
{
	TEST_ASSERT(err == 0, "Connection failed (%u)", err);
	connection = bt_conn_ref(conn);
	k_sem_give(&connected_sem);
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	ARG_UNUSED(conn);
	ARG_UNUSED(reason);
	bt_conn_drop(&connection);
	k_sem_give(&disconnected_sem);
}

static void security_changed(struct bt_conn *conn, bt_security_t level, enum bt_security_err err)
{
	ARG_UNUSED(conn);
	if (err == BT_SECURITY_ERR_SUCCESS) {
		reached_level = level;
		if (level == BT_SECURITY_L4) {
			TEST_ASSERT(cases[scenario_index].error == BT_SECURITY_ERR_SUCCESS,
				    "Negative case reached L4");
			k_sem_give(&encrypted_sem);
		}
	}
}

BT_CONN_CB_DEFINE(conn_cb) = {
	.connected = connected,
	.disconnected = disconnected,
	.security_changed = security_changed,
};

static void enter_password(struct k_work *work)
{
	const struct scenario *s = &cases[scenario_index];
	uint32_t password = is_central ? s->a : s->b;

	ARG_UNUSED(work);

	TEST_ASSERT(connection != NULL, "Passkey callback after disconnect");
	TEST_ASSERT(bt_conn_auth_passkey_entry(connection, password) == 0, "Passkey entry failed");
}

static K_WORK_DELAYABLE_DEFINE(passkey_work, enter_password);

static void passkey_entry(struct bt_conn *conn)
{
	const struct scenario *s = &cases[scenario_index];
	uint16_t delay = is_central ? s->delay_a : s->delay_b;

	ARG_UNUSED(conn);
	if (IS_ENABLED(CONFIG_BT_PASSKEY_KEYPRESS) && scenario_index == 0) {
		TEST_ASSERT(bt_conn_auth_keypress_notify(connection,
				BT_CONN_AUTH_KEYPRESS_ENTRY_STARTED) == 0, "Keypress send failed");
	}
	if (delay) {
		k_work_schedule(&passkey_work, K_MSEC(delay));
	} else {
		enter_password(NULL);
	}
}

static void auth_cancel(struct bt_conn *conn)
{
	ARG_UNUSED(conn);
	TEST_ASSERT(cases[scenario_index].error != BT_SECURITY_ERR_SUCCESS,
		    "Unexpected authentication cancellation");
}

#if defined(CONFIG_BT_PASSKEY_KEYPRESS)
static void keypress_notify(struct bt_conn *conn, enum bt_conn_auth_keypress type)
{
	ARG_UNUSED(conn);
	TEST_ASSERT(scenario_index == 0 && type == BT_CONN_AUTH_KEYPRESS_ENTRY_STARTED,
		    "Unexpected keypress notification");
	atomic_inc(&keypress_received);
}
#endif

static struct bt_conn_auth_cb auth_cb = {
	.passkey_entry = passkey_entry,
	.cancel = auth_cancel,
#if defined(CONFIG_BT_PASSKEY_KEYPRESS)
	.passkey_display_keypress = keypress_notify,
#endif
};

static void pairing_complete(struct bt_conn *conn, bool bonded)
{
	ARG_UNUSED(conn);
	ARG_UNUSED(bonded);
	TEST_ASSERT(cases[scenario_index].error == BT_SECURITY_ERR_SUCCESS,
		    "Negative case reported pairing complete");
	complete = true;
	k_sem_give(&pair_sem);
}

static void pairing_failed(struct bt_conn *conn, enum bt_security_err reason)
{
	ARG_UNUSED(conn);
	failed = true;
	failure_reason = reason;
	k_sem_give(&pair_sem);
}

static struct bt_conn_auth_info_cb info_cb = {
	.pairing_complete = pairing_complete,
	.pairing_failed = pairing_failed,
};

static void device_found(const bt_addr_le_t *addr, int8_t rssi, uint8_t type,
			 struct net_buf_simple *ad)
{
	struct bt_conn *pending = NULL;

	ARG_UNUSED(ad);
	if (type != BT_GAP_ADV_TYPE_ADV_IND || rssi < -70 || bt_le_scan_stop()) {
		return;
	}
	TEST_ASSERT(bt_conn_le_create(addr, BT_CONN_LE_CREATE_CONN, BT_LE_CONN_PARAM_DEFAULT,
				      &pending) == 0, "Create connection failed");
	bt_conn_unref(pending);
}

static uint8_t discovered(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			  struct bt_gatt_discover_params *params)
{
	ARG_UNUSED(conn);
	ARG_UNUSED(params);
	TEST_ASSERT(attr != NULL, "Test characteristic not found");
	value_handle = ((struct bt_gatt_chrc *)attr->user_data)->value_handle;
	k_sem_give(&io_sem);
	return BT_GATT_ITER_STOP;
}

static void wrote(struct bt_conn *conn, uint8_t err, struct bt_gatt_write_params *params)
{
	ARG_UNUSED(conn);
	ARG_UNUSED(params);
	TEST_ASSERT(err == 0, "Encrypted write failed (%u)", err);
	k_sem_give(&io_sem);
}

static uint8_t read_back(struct bt_conn *conn, uint8_t err, struct bt_gatt_read_params *params,
			 const void *data, uint16_t len)
{
	ARG_UNUSED(conn);
	ARG_UNUSED(params);
	TEST_ASSERT(err == 0 && data && len == sizeof(payload), "Encrypted read failed");
	TEST_ASSERT(memcmp(data, payload, len) == 0, "Encrypted echo differs");
	k_sem_give(&io_sem);
	return BT_GATT_ITER_STOP;
}

static void encrypted_echo(void)
{
	struct bt_gatt_discover_params discover = {
		.uuid = VALUE_UUID, .func = discovered, .start_handle = 1,
		.end_handle = 0xffff, .type = BT_GATT_DISCOVER_CHARACTERISTIC,
	};
	struct bt_gatt_write_params write = {.func = wrote, .data = payload,
		.length = sizeof(payload)};
	struct bt_gatt_read_params read = {.func = read_back, .handle_count = 1};

	for (int i = 0; i < sizeof(payload); i++) {
		payload[i] = 0xa0 + i + scenario_index;
	}
	TEST_ASSERT(bt_gatt_discover(connection, &discover) == 0, "Discover failed");
	wait_event(&io_sem, "discovery");
	write.handle = value_handle;
	TEST_ASSERT(bt_gatt_write(connection, &write) == 0, "Write start failed");
	wait_event(&io_sem, "write response");
	read.single.handle = value_handle;
	TEST_ASSERT(bt_gatt_read(connection, &read) == 0, "Read start failed");
	wait_event(&io_sem, "read response");
	printk("SPAKE encrypted GATT echo verified: 8 bytes written and read back\n");
}

static void run(bool central)
{
	TEST_START("SPAKE direct regression");
	is_central = central;
	TEST_ASSERT(bk_sync_init() == 0, "Sync init failed");
	TEST_ASSERT(bt_enable(NULL) == 0, "Bluetooth init failed");
	bt_set_bondable(false);
	TEST_ASSERT(bt_conn_auth_cb_register(&auth_cb) == 0, "Auth register failed");
	TEST_ASSERT(bt_conn_auth_info_cb_register(&info_cb) == 0, "Info register failed");
	if (central) {
		test_spake_crypto();
	}
	barrier();
	for (scenario_index = 0; scenario_index < ARRAY_SIZE(cases); scenario_index++) {
		const struct scenario *s = &cases[scenario_index];
		int64_t start = k_uptime_get();

		complete = failed = false;
		atomic_clear(&keypress_received);
		reached_level = BT_SECURITY_L1;
		failure_reason = BT_SECURITY_ERR_SUCCESS;
		stored_len = 0;
		k_sem_reset(&pair_sem);
		k_sem_reset(&encrypted_sem);
		k_sem_reset(&io_sem);
		k_sem_reset(&written_sem);
		bt_smp_spake_test_fault(central ? s->fault : BT_SPAKE_TEST_NONE);
		barrier();
		if (central) {
			TEST_ASSERT(bt_le_scan_start(BT_LE_SCAN_ACTIVE, device_found) == 0,
				    "Scan failed");
		} else {
			TEST_ASSERT(bt_le_adv_start(BT_LE_ADV_CONN_FAST_1, NULL, 0, NULL, 0) == 0,
				    "Advertising failed");
		}
		wait_event(&connected_sem, "connection");
		if (central) {
			TEST_ASSERT(bt_conn_set_security(connection, BT_SECURITY_L4) == 0,
				    "Security request failed");
		}
		wait_event(&pair_sem, "pairing result");
		if (s->error == BT_SECURITY_ERR_SUCCESS) {
			TEST_ASSERT(complete && !failed, "%s failed (%d)", s->name, failure_reason);
			wait_event(&encrypted_sem, "encryption");
			TEST_ASSERT(reached_level == BT_SECURITY_L4, "Expected L4");
			if (central) {
				encrypted_echo();
			} else {
				wait_event(&written_sem, "encrypted write");
			}
		} else {
			TEST_ASSERT(failed && !complete && reached_level < BT_SECURITY_L4,
				    "Expected explicit rejection");
			TEST_ASSERT(failure_reason == s->error, "%s: reason %d, expected %d",
				    s->name, failure_reason, s->error);
		}
		barrier();
		if (IS_ENABLED(CONFIG_BT_PASSKEY_KEYPRESS) && scenario_index == 0) {
			TEST_ASSERT(atomic_get(&keypress_received) == 1,
				    "Keypress was not delivered");
			printk("SPAKE keypress notification received role=%s\n",
			       central ? "A" : "B");
		}
		printk("SPAKE CASE %s PASS role=%s elapsed_ms=%lld reason=%d\n", s->name,
		       central ? "A" : "B", (long long)(k_uptime_get() - start), failure_reason);
		if (central) {
			TEST_ASSERT(bt_conn_disconnect(connection, BT_HCI_ERR_REMOTE_USER_TERM_CONN)
				    == 0, "Disconnect failed");
		}
		wait_event(&disconnected_sem, "disconnect");
		(void)k_work_cancel_delayable(&passkey_work);
		TEST_ASSERT(bt_unpair(BT_ID_DEFAULT, BT_ADDR_LE_ANY) == 0, "Unpair failed");
		/* Let connection recycling and any invalidated crypto job finish. */
		k_sleep(K_MSEC(100));
		barrier();
	}
	TEST_PASS("All SPAKE direct scenarios passed");
}

static void central(void) { run(true); }
static void peripheral(void) { run(false); }

static const struct bst_test_instance instances[] = {
	{.test_id = "central", .test_main_f = central},
	{.test_id = "peripheral", .test_main_f = peripheral},
	BSTEST_END_MARKER,
};

static struct bst_test_list *install(struct bst_test_list *tests)
{
	return bst_add_tests(tests, instances);
}

bst_test_install_t test_installers[] = {install, NULL};

int main(void)
{
	bst_main();
	return 0;
}
