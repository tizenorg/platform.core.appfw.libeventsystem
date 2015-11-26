/**
 * event system low-level API
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlog.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <glib.h>
#include <gio/gio.h>
#include <eventsystem.h>
#include <fcntl.h>

#undef LOG_TAG
#define LOG_TAG "eventsystem"

#define SYS_EVENT_NAME_PREFIX "tizen.system.event"
#define EVENT_SYSTEM_PREFIX "eventsystem.id_"
#define EVENT_SYSTEM_PREFIX_LEN 15
#define EVENT_SYSTEM_MEMBER "eventsystem"
#define VALID_COUNT_OF_EVENTNAME_TOKEN 3
#define VALID_LAST_COUNT_FOR_EVENTNAME (VALID_COUNT_OF_EVENTNAME_TOKEN + 1)
#define MAX_COUNT_FOR_EVENTNAME_CHECK (VALID_LAST_COUNT_FOR_EVENTNAME + 1)

#define _E(fmt, arg...) LOGE(fmt, ##arg)
#define _D(fmt, arg...) LOGD(fmt, ##arg)
#define _W(fmt, arg...) LOGW(fmt, ##arg)
#define _I(fmt, arg...) LOGI(fmt, ##arg)

#define retvm_if(expr, val, fmt, arg...) do { \
	if (expr) { \
		_E(fmt, ##arg); \
		_E("(%s) -> %s() return", #expr, __func__); \
		return val; \
	} \
} while (0)

#define retv_if(expr, val) do { \
	if (expr) { \
		_E("(%s) -> %s() return", #expr, __func__); \
		return val; \
	} \
} while (0)

#define tryvm_if(expr, val, fmt, arg...) do { \
	 if (expr) { \
		_E("(%s) "fmt, #expr, ##arg); \
		val; \
		goto catch; \
	} \
} while (0)

pthread_mutex_t send_sync_lock = PTHREAD_MUTEX_INITIALIZER;

static GList *system_event_list;
static int _initialized;
static GHashTable *check_tbl;
static GHashTable *filter_tbl;

typedef struct eventmap {
	char *event_name;
	char *interface_name;
	char *member_name;
	guint reg_id;
	GBusType bus_type;
	int event_type;
	union {
		eventsystem_cb es_cb;
		eventsystem_handler ep_cb;
	};
} eventmap_s;

typedef struct eventinfo {
	char *event_name;
	char *destination_name;
	char *interface_name;
	char *object_path;
	char *member_name;
	bool is_user_event;
	bundle *event_data;
} eventinfo_s;

typedef struct sysevent_info {
	guint owner_id;
	guint owner_id_session;
	char *own_name_system_bus;
	char *own_name_session_bus;
} sysevent_info_s;
static sysevent_info_s s_info;

static int __eventsystem_check_user_send_validation(const char *event_name);
static int __eventsystem_requet_destination_list(const char *event_name, GList **dest_list);
static int __eventsystem_check_sender_validation(int sender_pid,
		const char *event_name, char **sender);

static int __event_compare_name_cb(gconstpointer a, gconstpointer b)
{
	eventmap_s *key1 = (eventmap_s *)a;
	eventmap_s *key2 = (eventmap_s *)b;
	return strcmp(key1->interface_name, key2->interface_name) |
			strcmp(key1->member_name, key2->member_name);
}

static int __event_compare_reg_id_cb(gconstpointer a, gconstpointer b)
{
	eventmap_s *key1 = (eventmap_s *)a;
	eventmap_s *key2 = (eventmap_s *)b;
	return !(key1->reg_id == key2->reg_id);
}

static void __initialize(void)
{
#if (GLIB_MAJOR_VERSION <= 2 && GLIB_MINOR_VERSION < 36)
	g_type_init();
#endif

	_initialized = 1;
}

static int __eventsystem_get_sender_pid(GDBusConnection *conn, const char *sender_name)
{
	GDBusMessage *msg = NULL;
	GDBusMessage *reply = NULL;
	GError *err = NULL;
	GVariant *body;
	int pid = 0;

	msg = g_dbus_message_new_method_call("org.freedesktop.DBus", "/org/freedesktop/DBus",
		"org.freedesktop.DBus", "GetConnectionUnixProcessID");
	if (!msg) {
		_E("Can't allocate new method call");
		goto out;
	}

	g_dbus_message_set_body(msg, g_variant_new("(s)", sender_name));
	reply = g_dbus_connection_send_message_with_reply_sync(conn, msg,
		G_DBUS_SEND_MESSAGE_FLAGS_NONE, -1, NULL, NULL, &err);

	if (!reply) {
		if (err != NULL) {
			_E("Failed to get pid [%s]", err->message);
			g_error_free(err);
		}
		goto out;
	}

	body = g_dbus_message_get_body(reply);
	g_variant_get(body, "(u)", &pid);

out:
	if (msg)
		g_object_unref(msg);
	if (reply)
		g_object_unref(reply);

	return pid;
}

static char *__get_object_path(char *interface_name)
{
	int i;
	char *object_path = (char *)calloc(strlen(interface_name), sizeof(char)+2);

	if (object_path == NULL) {
		_E("failed to allocate memory");
		return NULL;
	}

	object_path[0] = '/';

	for (i = 0 ; interface_name[i] ; i++) {

		if (interface_name[i] == '.') {
			object_path[i+1] = '/';
		} else {
			object_path[i+1] = interface_name[i];
		}
	}

	return object_path;
}

static char *__get_encoded_interface_name(char *interface_name)
{
	char *evtid = NULL;
	int evtid_len = 0;
	gchar *encoded_value;

	encoded_value = g_compute_checksum_for_string(G_CHECKSUM_MD5,
		interface_name, strlen(interface_name));

	evtid_len = EVENT_SYSTEM_PREFIX_LEN + strlen(encoded_value) + 1;

	evtid = (char *)calloc(evtid_len, sizeof(char));
	if (evtid == NULL) {
		_D("memory alloc failed");
		g_free(encoded_value);
		return NULL;
	}

	snprintf(evtid, evtid_len, "%s%s", EVENT_SYSTEM_PREFIX, (char *)encoded_value);

	g_free(encoded_value);

	return evtid;
}

static char *__get_member_name_from_eventname(char *event_name)
{
	char *ptr = NULL;
	char *ptr_last = NULL;
	char *temp_name = NULL;
	char *member_name = NULL;
	char *save_ptr = NULL;
	int count = 0;

	temp_name = strdup(event_name);
	if (temp_name == NULL) {
		_E("out of memory");
		return NULL;
	}

	ptr = strtok_r(temp_name, ".", &save_ptr);
	if (ptr == NULL) {
		_E("invalid event_name(%s), count(%d)", event_name, count);
		FREE_AND_NULL(temp_name);
		return NULL;
	}
	count++;

	while (count < MAX_COUNT_FOR_EVENTNAME_CHECK) {
		ptr = strtok_r(NULL, ".", &save_ptr);
		if (ptr == NULL)
			break;
		/* _D("(%d)ptr(%s)(%d)", count, ptr, strlen(ptr)); */
		ptr_last = ptr;
		count++;
	}
	FREE_AND_NULL(temp_name);

	if (count != VALID_LAST_COUNT_FOR_EVENTNAME) {
		_E("invalid event_name(%s), count(%d)", event_name, count);
		return NULL;
	}

	if (ptr_last) {
		/* _D("new member_name(%s)(%d)", ptr_last, strlen(ptr_last)); */
		member_name = strdup(ptr_last);
		if (!member_name) {
			_E("out_of_memory");
			return NULL;
		}
	} else {
		_E("ptr_last is NULL");
		return NULL;
	}

	_D("member_name(%s)", member_name);

	return member_name;
}

static int __check_validation_usrevent_sender(int sender_pid,
		const char *interface_name, const char *event_name)
{
	char *sender_id = NULL;
	char *key = NULL;
	char *val = NULL;

	if (__eventsystem_check_sender_validation(sender_pid,
		event_name, &sender_id) < 0) {
		_E("invalid user-event sender");
		return ES_R_EINVAL;
	}

	if (sender_id == NULL) {
		_E("sender_id is null");
		return ES_R_EINVAL;
	}

	key = strdup(interface_name);
	if (key == NULL) {
		_E("out of memory");
		return ES_R_ENOMEM;
	}

	val = strdup(sender_id);
	if (val == NULL) {
		_E("out of memory");
		free(key);
		return ES_R_ENOMEM;
	}

	g_hash_table_insert(filter_tbl, key, val);

	return ES_R_OK;
}

static int __check_validation_user_defined_name(const char *event_name)
{
	char *event_id = NULL;
	char *key = NULL;
	int ret = 1;

	if (check_tbl == NULL) {
		check_tbl = g_hash_table_new(g_str_hash, g_str_equal);
	}

	event_id = (char *)g_hash_table_lookup(check_tbl, event_name);

	if (event_id == NULL) {
		if (__eventsystem_check_user_send_validation(event_name) < 0) {
			_E("invalid user-event name");
			ret = 0;
		} else {
			key = strdup(event_name);
			if (key == NULL) {
				_E("out_of_memory");
				ret = 0;
			} else {
				g_hash_table_insert(check_tbl, key, key);
			}
		}
	}

	return ret;
}

static int __check_interface_validation_user(char *interface_name)
{
	int ret = 1;
	int len = strlen(EVENT_SYSTEM_PREFIX);

	if (strncmp(interface_name, EVENT_SYSTEM_PREFIX, len) != 0) {
		ret = 0;
	}

	return ret;
}

static int __check_eventname_validation_user(char *event_name)
{
	int ret = 1;
	int len = strlen(USER_EVENT_NAME_PREFIX);

	if (strncmp(event_name, USER_EVENT_NAME_PREFIX, len) != 0) {
		ret = 0;
	}

	return ret;
}

static int __check_eventname_validation_system(char *event_name)
{
	int ret = 1;
	int len = strlen(SYS_EVENT_NAME_PREFIX);

	if (strncmp(event_name, SYS_EVENT_NAME_PREFIX, len) != 0) {
		ret = 0;
	}

	return ret;
}

static int __get_gdbus_shared_connection(GDBusConnection **connection, GBusType bus_type,
		eventsystem_event_type event_type)
{
	GError *error = NULL;
	guint owner_id = 0;

	if (!_initialized) {
		__initialize();
	}

	*connection = g_bus_get_sync(bus_type, NULL, &error);
	if (*connection == NULL) {
		if (error != NULL) {
			_E("Failed to get dbus [%s], bus_type [%d]",
				error->message, bus_type);
			g_error_free(error);
		}
		return ES_R_ERROR;
	}

	if (((bus_type == G_BUS_TYPE_SYSTEM && !s_info.owner_id) ||
		(bus_type == G_BUS_TYPE_SESSION && !s_info.owner_id_session))) {
		gchar *guid = NULL;
		char own_name[128] = {0, };

		guid = g_dbus_generate_guid();
		if (guid == NULL) {
			_E("failed to get guid");
			return ES_R_ERROR;
		}
		snprintf(own_name, 128, "%s.%s.id%s_%d", "event.busname",
			(bus_type == G_BUS_TYPE_SESSION ? "session" : "system"),
			guid, getpid());
		g_free(guid);

		_D("bus_name is [%s]", own_name);
		owner_id = g_bus_own_name_on_connection(*connection, own_name,
			G_BUS_NAME_OWNER_FLAGS_NONE,
			NULL, NULL, NULL, NULL);
		if (!owner_id) {
			_E("g_bus_own_name_on_connection, error");
			return ES_R_ERROR;
		}

		if (bus_type == G_BUS_TYPE_SESSION && event_type == ES_TYPE_USER) {
			/* set same name on system-bus */
			GDBusConnection *conn_system = NULL;

			error = NULL;
			conn_system = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
			if (conn_system == NULL) {
				_E("failed to get system connection");
				if (error != NULL) {
					_E("error(%s)", error->message);
					g_error_free(error);
				}
				return ES_R_ERROR;
			} else {
				owner_id = g_bus_own_name_on_connection(conn_system,
					own_name, G_BUS_NAME_OWNER_FLAGS_NONE,
					NULL, NULL, NULL, NULL);
				if (!owner_id) {
					_E("g_bus_own_name_on_connection(for system), error");
					g_object_unref(conn_system);
					return ES_R_ERROR;
				}

				g_object_unref(conn_system);
			}
		}

		if (bus_type == G_BUS_TYPE_SESSION) {
			s_info.owner_id_session = owner_id;
			s_info.own_name_session_bus = strdup(own_name);
			if (s_info.own_name_session_bus == NULL) {
				_E("out of memory");
				return ES_R_ERROR;
			}
		} else {
			s_info.owner_id = owner_id;
			s_info.own_name_system_bus = strdup(own_name);
			if (s_info.own_name_system_bus == NULL) {
				_E("out of memory");
				return ES_R_ERROR;
			}
		}
	}

	return ES_R_OK;
}

static void __eventsystem_event_handler(GDBusConnection *connection,
		const gchar *sender_name, const gchar *object_path,
		const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data)
{
	int len;
	eventmap_s em;
	GList *cb_list = NULL;
	bundle *buf = NULL;
	bundle_raw *raw = NULL;

	em.interface_name = (char *)interface_name;
	em.member_name = (char *)signal_name;

	_D("sender_name(%s), interface_name(%s), signal_name(%s)",
		sender_name, interface_name, signal_name);

	cb_list = g_list_find_custom(system_event_list, &em,
		(GCompareFunc)__event_compare_name_cb);
	if (cb_list == NULL) {
		return;
	}

	g_variant_get(parameters, "(us)", &len, &raw);

	buf = bundle_decode((bundle_raw *)raw, len);

	em.event_name = ((eventmap_s *)cb_list->data)->event_name;
	em.ep_cb = ((eventmap_s *)cb_list->data)->ep_cb;
	if (em.ep_cb) {
		em.ep_cb(em.event_name, buf, user_data);
	}

	bundle_free_encoded_rawdata(&raw);
	bundle_free(buf);
}

static void __eventsystem_application_event_handler(int sender_pid,
		const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data)
{
	GList *cb_list = NULL;
	eventmap_s em;
	bundle_raw *raw = NULL;
	int len;

	em.interface_name = (char *)interface_name;
	em.member_name = (char *)signal_name;

	cb_list = g_list_find_custom(system_event_list, &em,
		(GCompareFunc)__event_compare_name_cb);

	if (cb_list == NULL) {
		_E("not interested event");
		return;
	}

	em.event_name = ((eventmap_s *)cb_list->data)->event_name;

	if (sender_pid > 0 && __check_interface_validation_user((char *)interface_name)) {
		if (__check_validation_usrevent_sender(sender_pid,
			(const char *)interface_name, em.event_name) < 0) {
			_E("invalid sender");
			return;
		}
	}

	g_variant_get(parameters, "(us)", &len, &raw);
	em.es_cb = ((eventmap_s *)cb_list->data)->es_cb;
	if (em.es_cb) {
		em.es_cb(em.event_name, raw, len, user_data);
	}

	bundle_free_encoded_rawdata(&raw);
}

/**
 * application-use filter for user-event
 */
static void __eventsystem_filter_userevent_for_application(GDBusConnection *connection,
		const gchar *sender_name, const gchar *object_path,
		const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data)
{
	char *sender_id = NULL;
	int sender_pid = -1;

	_D("sender_name(%s), interface_name(%s)", sender_name, interface_name);

	if (filter_tbl == NULL) {
		filter_tbl = g_hash_table_new(g_str_hash, g_str_equal);
	}

	sender_id = (char *)g_hash_table_lookup(filter_tbl, interface_name);

	if (sender_id == NULL) {
		sender_pid = __eventsystem_get_sender_pid(connection, sender_name);
		if (sender_pid <= 0) {
			_E("failed to get pid of sender(%s)", sender_name);
			return;
		}
		_D("sender_pid(%d)", sender_pid);
	}

	__eventsystem_application_event_handler(sender_pid, interface_name,
		signal_name, parameters, user_data);
}

/**
 * application-use filter for system-event
 */
static void __eventsystem_filter_sysevent_for_application(GDBusConnection *connection,
		const gchar *sender_name, const gchar *object_path,
		const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data)
{
	_D("sender_name(%s), interface_name(%s)", sender_name, interface_name);

	__eventsystem_application_event_handler(-1, interface_name,
		signal_name, parameters, user_data);
}

/**
 * internal-use filter for user-event
 */
static void __eventsystem_filter_userevent_for_internal(GDBusConnection *connection,
		const gchar *sender_name, const gchar *object_path,
		const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data)
{
	_D("sender_name(%s), interface_name(%s), signal_name(%s)",
		sender_name, interface_name, signal_name);

	__eventsystem_event_handler(connection, sender_name,
		object_path, interface_name, signal_name, parameters, user_data);
}

/**
 * internal-use filter for system-event
 */
static void __eventsystem_filter_sysevent_for_internal(GDBusConnection *connection,
		const gchar *sender_name, const gchar *object_path,
		const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data)
{
	_D("sender_name(%s), interface_name(%s), signal_name(%s)",
		sender_name, interface_name, signal_name);

	__eventsystem_event_handler(connection, sender_name,
		object_path, interface_name, signal_name, parameters, user_data);
}

static int __eventsystem_register_event_internal(const char *event_name,
		eventmap_s **em_s, void *user_data)
{
	eventmap_s *em = NULL;
	char *interface_name = NULL;
	char *object_path = NULL;
	char *member_name = NULL;
	char *sender_name = NULL;
	GDBusSignalCallback filter;
	GBusType bus_type;
	guint subscription_id = 0;
	int ret = 0;
	int evt_type = ES_TYPE_UNKNOWN;
	GDBusConnection *conn = NULL;

	if (__check_eventname_validation_system((char *)event_name)) {
		evt_type = ES_TYPE_SYSTEM;
	} else if (__check_eventname_validation_user((char *)event_name)) {
		evt_type = ES_TYPE_USER;
	} else {
		evt_type = ES_TYPE_UNKNOWN;
		_E("unknown type event(%s)", event_name);
		return ES_R_EINVAL;
	}

	if (evt_type == ES_TYPE_SYSTEM) {
		interface_name = strdup(SYS_EVENT_NAME_PREFIX);
		if (interface_name == NULL) {
			_E("out of memory");
			ret = ES_R_ENOMEM;
			goto out_1;
		}

		member_name = __get_member_name_from_eventname((char *)event_name);
		if (member_name == NULL) {
			_E("invalid member_name");
			ret = ES_R_ERROR;
			goto out_2;
		}

		if (!g_dbus_is_member_name(member_name)) {
			_E("invalid member name");
			ret = ES_R_EINVAL;
			goto out_3;
		}
		filter = __eventsystem_filter_sysevent_for_internal;
	} else {
		interface_name = __get_encoded_interface_name((char *)event_name);
		if (!interface_name) {
			_E("interface_name is NULL");
			ret = ES_R_ERROR;
			goto out_1;
		}
		if (!g_dbus_is_interface_name(interface_name)) {
			_E("invalid interface_name(%s)", interface_name);
			ret = ES_R_EINVAL;
			goto out_2;
		}
		member_name = strdup(EVENT_SYSTEM_MEMBER);
		if (!member_name) {
			_E("out_of_memory");
			ret = ES_R_ERROR;
			goto out_2;
		}
		filter = __eventsystem_filter_userevent_for_internal;
	}

	object_path = __get_object_path(interface_name);
	if (!object_path) {
		_E("object_path is NULL");
		ret = ES_R_ERROR;
		goto out_3;
	}
	sender_name = NULL;

	bus_type = G_BUS_TYPE_SYSTEM;

	if (__get_gdbus_shared_connection(&conn, bus_type, evt_type) < 0) {
		_E("getting gdbus-connetion error");
		goto out_4;
	}

	subscription_id = g_dbus_connection_signal_subscribe(conn,
		sender_name, /* sender */
		interface_name,
		member_name, /* member */
		object_path, /* object_path */
		NULL, /* arg0 */
		G_DBUS_SIGNAL_FLAGS_NONE,
		filter,
		user_data,
		NULL); /* user_data_free_func */

	_D("event_name(%s), interface_name(%s)", event_name, interface_name);
	_D("member_name(%s), subscription_id(%d), bus_type(%d)",
		member_name, subscription_id, bus_type);

	if (subscription_id != 0) {
		em = calloc(1, sizeof(eventmap_s));
		if (!em) {
			_E("memory alloc failed");
			ret = ES_R_ENOMEM;
		} else {
			em->interface_name = strdup(interface_name);
			em->member_name = strdup(member_name);
			em->event_name = strdup(event_name);
			em->bus_type = bus_type;
			em->reg_id = subscription_id;
			em->event_type = evt_type;

			if (!em->interface_name || !em->member_name || !em->event_name) {
				_E("out_of_memory");
				FREE_AND_NULL(em->interface_name);
				FREE_AND_NULL(em->member_name);
				FREE_AND_NULL(em->event_name);
				FREE_AND_NULL(em);
				ret = ES_R_ENOMEM;
				goto out_4;
			}

			*em_s = em;
			ret = ES_R_OK;
		}
	} else {
		_D("dbus subscribe: error(%d), event(%s)", subscription_id, event_name);
		ret = ES_R_ERROR;
	}

out_4:
	FREE_AND_NULL(object_path);
out_3:
	FREE_AND_NULL(member_name);
out_2:
	FREE_AND_NULL(interface_name);
out_1:
	if (conn) {
		g_object_unref(conn);
	}

	return ret;
}

/**
 * function : register the event
 */
int eventsystem_register_event(const char *event_name, unsigned int *reg_id,
		eventsystem_handler callback, void *user_data)
{
	eventmap_s *em = NULL;
	int ret = ES_R_ERROR;

	retvm_if(!g_dbus_is_interface_name(event_name), ES_R_EINVAL,
		"Invalid argument : event_name(%s)", event_name);
	retvm_if(!reg_id, ES_R_EINVAL, "Invalid argument : reg_id");
	retvm_if(!callback, ES_R_EINVAL, "Invalid argument : callback");

	if (!_initialized) {
		__initialize();
	}

	ret = __eventsystem_register_event_internal(event_name, &em, user_data);

	if (ret == ES_R_OK && em) {
		em->ep_cb = callback;
		system_event_list = g_list_append(system_event_list, em);
		*reg_id = em->reg_id;
		ret = ES_R_OK;
	} else {
		_E("error, ret(%d), em(%s)", ret, em);
	}

	return ret;
}

/**
 * function : unregister the event
 */
int eventsystem_unregister_event(unsigned int reg_id)
{
	eventmap_s em;
	eventmap_s *em_data = NULL;
	GBusType bus_type;
	GList *cb_list = NULL;
	GDBusConnection *conn = NULL;
	eventsystem_event_type evt_type;

	retvm_if(reg_id == 0, ES_R_EINVAL, "Invalid argument : reg_id");

	if (!_initialized) {
		__initialize();
	}

	em.reg_id = reg_id;
	cb_list = g_list_find_custom(system_event_list, &em,
		(GCompareFunc)__event_compare_reg_id_cb);
	if (cb_list) {
		em_data = (eventmap_s *)cb_list->data;

		bus_type = em_data->bus_type;
		evt_type = em_data->event_type;

		_D("unsubscribe: reg_id(%d), bus_type(%d)", reg_id, bus_type);

		if (__get_gdbus_shared_connection(&conn, bus_type, evt_type) < 0) {
			_E("getting gdbus-connetion error");
			return ES_R_ERROR;
		}
		g_dbus_connection_signal_unsubscribe(conn, reg_id);

		system_event_list = g_list_remove(system_event_list, cb_list->data);

		FREE_AND_NULL(em_data->interface_name);
		FREE_AND_NULL(em_data->member_name);
		FREE_AND_NULL(em_data->event_name);
		FREE_AND_NULL(em_data);
		g_object_unref(conn);
	}

	return ES_R_OK;
}

static int __eventsystem_send_event(GDBusConnection *conn, eventinfo_s *evti, bundle *data)
{
	GError *error = NULL;
	GVariant *param = NULL;
	gboolean ret;

	bundle_raw *raw = NULL;
	bundle *buf = data;
	int len;

	bundle_encode(buf, &raw, &len);

	param = g_variant_new("(us)", len, raw);
	ret = g_dbus_connection_emit_signal(conn,
		evti->destination_name,
		evti->object_path,
		evti->interface_name,
		evti->member_name,
		param,
		&error);

	_D("interface_name(%s)", evti->interface_name);
	_D("object_path(%s)", evti->object_path);
	_D("member_name(%s)", evti->member_name);

	bundle_free_encoded_rawdata(&raw);

	if (ret == FALSE) {
		_E("Unable to connect to dbus: %s", error->message);
		g_error_free(error);
		return ES_R_ERROR;
	}

	return ES_R_OK;
}

static void __eventsystem_free_trusted_list(gpointer data)
{
	char *name = (char *)data;

	FREE_AND_NULL(name);
}

static int __eventsystem_send_trusted_event(GDBusConnection *conn, eventinfo_s *evti,
		bundle *data, GList *dest_list)
{
	GList *tmp_list = NULL;
	int ret = 0;

	if (dest_list) {
		tmp_list = g_list_first(dest_list);

		while (tmp_list != NULL) {
			char *dest_name = (char *)tmp_list->data;
			if (dest_name && dest_name[0] != '\0') {
				_D("dest_name(%s)", dest_name);
				evti->destination_name = dest_name;
				ret = __eventsystem_send_event(conn, evti, data);
				if (ret != ES_R_OK) {
					_E("send error");
					ret = ES_R_ERROR;
					break;
				}
			}
			tmp_list = g_list_next(tmp_list);
		}
		g_list_free_full(dest_list, __eventsystem_free_trusted_list);
	} else {
		_E("dest_list is null");
	}

	return ES_R_OK;
}

/**
 * function : send the user-event
 */
int eventsystem_send_user_event(const char *event_name, bundle *data, bool is_trusted)
{
	int ret = 0;

	/* check validation */
	retvm_if(!event_name, ES_R_EINVAL, "Invalid argument : event_name is NULL");
	retvm_if(!data, ES_R_EINVAL, "Invalid argument : data is NULL");
	retvm_if(!__check_eventname_validation_user((char *)event_name), ES_R_EINVAL,
		"Invalid argument : event_name(%s)", event_name);

	if (!__check_validation_user_defined_name(event_name)) {
		_E("Invalid event name(%s)", event_name);
		return ES_R_EINVAL;
	}

	eventinfo_s *evti = NULL;
	evti = calloc(1, sizeof(eventinfo_s));
	if (!evti) {
		_E("memory alloc failed");
		return ES_R_ENOMEM;
	}
	evti->event_name = strdup(event_name);
	if (!evti->event_name) {
		_E("memory alloc failed");
		ret = ES_R_ENOMEM;
		goto out_1;
	}

	evti->interface_name = __get_encoded_interface_name(evti->event_name);
	if (!evti->interface_name) {
		_E("interface_name is NULL");
		ret = ES_R_ERROR;
		goto out_2;
	}
	evti->member_name = strdup(EVENT_SYSTEM_MEMBER);
	if (!evti->member_name) {
		_E("memory alloc failed");
		ret = ES_R_ENOMEM;
		goto out_3;
	}

	evti->object_path = __get_object_path(evti->interface_name);
	if (!evti->object_path) {
		_E("object_path is NULL");
		ret = ES_R_ERROR;
		goto out_4;
	}

	evti->destination_name = NULL;
	evti->is_user_event = true;

	GDBusConnection *conn = NULL;
	if (__get_gdbus_shared_connection(&conn, G_BUS_TYPE_SESSION, ES_TYPE_USER) == ES_R_OK) {
		if (is_trusted) {
			GList *dest_list = NULL;
			ret = __eventsystem_requet_destination_list(evti->event_name, &dest_list);
			if (ret < 0) {
				_E("failed to get dest list");
				ret = ES_R_ERROR;
			} else {
				ret = __eventsystem_send_trusted_event(conn, evti,
					data, dest_list);
			}
		} else {
			ret = __eventsystem_send_event(conn, evti, data);
		}
	} else {
		_E("getting gdbus-connetion error");
		ret = ES_R_ERROR;
	}

	if (conn) {
		g_object_unref(conn);
	}
	FREE_AND_NULL(evti->object_path);
out_4:
	FREE_AND_NULL(evti->member_name);
out_3:
	FREE_AND_NULL(evti->interface_name);
out_2:
	FREE_AND_NULL(evti->event_name);
out_1:
	FREE_AND_NULL(evti);

	return ret;
}

/**
 * function : send the system-event
 */
int eventsystem_send_system_event(const char *event_name, bundle *data)
{
	int ret = 0;

	pthread_mutex_lock(&send_sync_lock);

	/* check validation */
	tryvm_if(!event_name, ret = ES_R_EINVAL, "Invalid argument : event_name is NULL");
	tryvm_if(!data, ret = ES_R_EINVAL, "Invalid argument : data is NULL");
	tryvm_if(!__check_eventname_validation_system((char *)event_name), ret = ES_R_EINVAL,
		"Invalid argument : event_name(%s)", event_name);
	tryvm_if(!g_dbus_is_interface_name(event_name), ret = ES_R_EINVAL,
		"Invalid argument : event_name(%s)", event_name);

	_D("event_name(%s)", event_name);

	eventinfo_s *evti = NULL;
	evti = calloc(1, sizeof(eventinfo_s));
	if (!evti) {
		_E("memory alloc failed");
		pthread_mutex_unlock(&send_sync_lock);
		return ES_R_ENOMEM;
	}
	evti->event_name = strdup(event_name);
	if (!evti->event_name) {
		_E("out_of_memory");
		ret = ES_R_ENOMEM;
		goto out_1;
	}
	evti->interface_name = strdup(SYS_EVENT_NAME_PREFIX);
	if (!evti->interface_name) {
		_E("out of memory");
		ret = ES_R_ENOMEM;
		goto out_2;
	}
	evti->member_name = __get_member_name_from_eventname(evti->event_name);
	if (!evti->member_name) {
		_E("member_name is NULL");
		ret = ES_R_ERROR;
		goto out_3;
	}
	if (!g_dbus_is_member_name(evti->member_name)) {
		_E("Invalid member_name(%s)", evti->member_name);
		ret = ES_R_EINVAL;
		goto out_4;
	}
	evti->object_path = __get_object_path(evti->interface_name);
	if (!evti->object_path) {
		_E("object_path is NULL");
		ret = ES_R_ERROR;
		goto out_4;
	}
	evti->destination_name = NULL;
	evti->is_user_event = false;

	GDBusConnection *conn = NULL;
	if (__get_gdbus_shared_connection(&conn, G_BUS_TYPE_SYSTEM, ES_TYPE_SYSTEM) == ES_R_OK) {
		ret = __eventsystem_send_event(conn, evti, data);
	} else {
		_E("getting gdbus-connection error");
		ret = ES_R_ERROR;
	}

	if (conn) {
		g_object_unref(conn);
	}
	FREE_AND_NULL(evti->object_path);
out_4:
	FREE_AND_NULL(evti->member_name);
out_3:
	FREE_AND_NULL(evti->interface_name);
out_2:
	FREE_AND_NULL(evti->event_name);
out_1:
	FREE_AND_NULL(evti);

catch:
	pthread_mutex_unlock(&send_sync_lock);

	return ret;
}

/**
 * function : request sending the event
 */
int eventsystem_request_sending_system_event(const char *event_name, bundle *data)
{
	int ret = 0;
	GDBusConnection *conn = NULL;
	GError *error = NULL;
	GDBusProxy *proxy = NULL;
	GVariant *param = NULL;
	GVariant *value = NULL;
	gint result = 0;
	bundle_raw *raw = NULL;
	int len = 0;

	_D("event_name(%s)", event_name);

	if (!_initialized) {
		__initialize();
	}

	if (__get_gdbus_shared_connection(&conn, G_BUS_TYPE_SYSTEM, ES_TYPE_SYSTEM) < 0) {
		_E("getting gdbus-connetion error");
		ret = ES_R_ERROR;
		goto out_1;
	}

	proxy = g_dbus_proxy_new_sync(conn,
		G_DBUS_PROXY_FLAGS_NONE, NULL,
		ESD_BUS_NAME, ESD_OBJECT_PATH, ESD_INTERFACE_NAME,
		NULL, &error);
	if (proxy == NULL) {
		_E("failed to create new proxy, error(%s)", error->message);
		g_error_free(error);
		ret = ES_R_ERROR;
		goto out_1;
	}

	bundle_encode(data, &raw, &len);

	param = g_variant_new("(ssi)", event_name, raw, len);
	value = g_dbus_proxy_call_sync(proxy, "RequestSendingEvent", param,
		G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (error != NULL) {
		_E("proxy call sync error(%s)", error->message);
		g_error_free(error);
		ret = ES_R_ERROR;
		goto out_2;
	}

	g_variant_get(value, "(i)", &result);

	_D("result(%d)", result);

	ret = ES_R_OK;

out_2:
	g_variant_unref(value);
out_1:
	if (conn) {
		g_object_unref(conn);
	}

	return ret;
}

static int __eventsystem_check_sender_validation(int sender_pid, const char *event_name,
		char **sender_id)
{
	int ret = ES_R_EINVAL;
	GDBusConnection *conn = NULL;
	GError *error = NULL;
	GDBusProxy *proxy = NULL;
	GVariant *param = NULL;
	GVariant *value = NULL;
	gint result = 0;

	if (!_initialized) {
		__initialize();
	}

	if (__get_gdbus_shared_connection(&conn, G_BUS_TYPE_SYSTEM, ES_TYPE_SYSTEM) < 0) {
		_E("getting gdbus-connetion error");
		ret = ES_R_ERROR;
		goto out_1;
	}

	proxy = g_dbus_proxy_new_sync(conn,
		G_DBUS_PROXY_FLAGS_NONE, NULL,
		ESD_BUS_NAME, ESD_OBJECT_PATH, ESD_INTERFACE_NAME,
		NULL, &error);
	if (proxy == NULL) {
		_E("failed to create new proxy, error(%s)", error->message);
		g_error_free(error);
		ret = ES_R_ERROR;
		goto out_1;
	}

	param = g_variant_new("(is)", sender_pid, event_name);
	value = g_dbus_proxy_call_sync(proxy, "CheckSenderValidation", param,
		G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (error != NULL) {
		_E("proxy call sync error(%s)", error->message);
		g_error_free(error);
		ret = ES_R_ERROR;
		goto out_2;
	}

	g_variant_get(value, "(is)", &result, sender_id);

	_D("result(%d)", result);

	if (result == 1) {
		ret = ES_R_OK;
	}
out_2:
	g_variant_unref(value);
out_1:
	if (conn) {
		g_object_unref(conn);
	}

	return ret;
}

static int __eventsystem_check_user_send_validation(const char *event_name)
{
	int ret = ES_R_EINVAL;
	GDBusConnection *conn = NULL;
	GError *error = NULL;
	GDBusProxy *proxy = NULL;
	GVariant *param = NULL;
	GVariant *value = NULL;
	gint result = 0;

	if (!_initialized) {
		__initialize();
	}

	if (__get_gdbus_shared_connection(&conn, G_BUS_TYPE_SYSTEM, ES_TYPE_SYSTEM) < 0) {
		_E("getting gdbus-connetion error");
		ret = ES_R_ERROR;
		goto out_1;
	}

	proxy = g_dbus_proxy_new_sync(conn,
		G_DBUS_PROXY_FLAGS_NONE, NULL,
		ESD_BUS_NAME, ESD_OBJECT_PATH, ESD_INTERFACE_NAME,
		NULL, &error);
	if (proxy == NULL) {
		_E("failed to create new proxy, error(%s)", error->message);
		g_error_free(error);
		ret = ES_R_ERROR;
		goto out_1;
	}

	param = g_variant_new("(s)", event_name);
	value = g_dbus_proxy_call_sync(proxy, "CheckUserSendValidation", param,
		G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (error != NULL) {
		_E("proxy call sync error(%s)", error->message);
		g_error_free(error);
		ret = ES_R_ERROR;
		goto out_2;
	}

	g_variant_get(value, "(i)", &result);

	_D("result(%d)", result);

	if (result == 1) {
		ret = ES_R_OK;
	}
out_2:
	g_variant_unref(value);
out_1:
	if (conn) {
		g_object_unref(conn);
	}

	return ret;
}

static int __eventsystem_check_privilege_validation(const char *event_name)
{
	int ret = ES_R_ENOTPERMITTED;
	GDBusConnection *conn = NULL;
	GError *error = NULL;
	GDBusProxy *proxy = NULL;
	GVariant *param = NULL;
	GVariant *value = NULL;
	gint result = 0;

	if (!_initialized) {
		__initialize();
	}

	if (__get_gdbus_shared_connection(&conn, G_BUS_TYPE_SYSTEM, ES_TYPE_SYSTEM) < 0) {
		_E("getting gdbus-connetion error");
		ret = ES_R_ERROR;
		goto out_1;
	}

	proxy = g_dbus_proxy_new_sync(conn,
		G_DBUS_PROXY_FLAGS_NONE, NULL,
		ESD_BUS_NAME, ESD_OBJECT_PATH, ESD_INTERFACE_NAME,
		NULL, &error);
	if (proxy == NULL) {
		_E("failed to create new proxy, error(%s)", error->message);
		g_error_free(error);
		ret = ES_R_ERROR;
		goto out_1;
	}

	param = g_variant_new("(s)", event_name);
	value = g_dbus_proxy_call_sync(proxy, "CheckPrivilegeValidation", param,
		G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (error != NULL) {
		_E("proxy call sync error(%s)", error->message);
		g_error_free(error);
		ret = ES_R_ERROR;
		goto out_2;
	}

	g_variant_get(value, "(i)", &result);

	_D("result(%d)", result);

	if (result == 1) {
		ret = ES_R_OK;
	}
out_2:
	g_variant_unref(value);
out_1:
	if (conn) {
		g_object_unref(conn);
	}

	return ret;
}

static int __eventsystem_setup_trusted_peer(const char *event_name, const char *dest_bus_name)
{
	int ret = ES_R_ERROR;
	GDBusConnection *conn = NULL;
	GError *error = NULL;
	GDBusProxy *proxy = NULL;
	GVariant *param = NULL;
	GVariant *value = NULL;
	gint result = 0;

	if (!_initialized) {
		__initialize();
	}

	if (__get_gdbus_shared_connection(&conn, G_BUS_TYPE_SYSTEM, ES_TYPE_SYSTEM) < 0) {
		_E("getting gdbus-connetion error");
		ret = ES_R_ERROR;
		goto out_1;
	}

	proxy = g_dbus_proxy_new_sync(conn,
		G_DBUS_PROXY_FLAGS_NONE, NULL,
		ESD_BUS_NAME, ESD_OBJECT_PATH, ESD_INTERFACE_NAME,
		NULL, &error);
	if (proxy == NULL) {
		_E("failed to create new proxy, error(%s)", error->message);
		g_error_free(error);
		ret = ES_R_ERROR;
		goto out_1;
	}

	param = g_variant_new("(ss)", event_name, dest_bus_name);

	value = g_dbus_proxy_call_sync(proxy, "SetupTrustedPeer", param,
		G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (error != NULL) {
		_E("proxy call sync error(%s)", error->message);
		g_error_free(error);
		ret = ES_R_ERROR;
		goto out_2;
	}

	g_variant_get(value, "(i)", &result);

	_D("result(%d)", result);

	if (result == 1) {
		ret = ES_R_OK;
	}
out_2:
	g_variant_unref(value);
out_1:
	if (conn) {
		g_object_unref(conn);
	}

	return ret;
}

static int __eventsystem_requet_destination_list(const char *event_name, GList **dest_list)
{
	int ret = ES_R_ERROR;
	GDBusConnection *conn = NULL;
	GError *error = NULL;
	GDBusProxy *proxy = NULL;
	GVariant *param = NULL;
	GVariant *value = NULL;
	GVariantIter *iter;
	gchar *str;
	char *dest_name = NULL;
	gint result = 0;

	if (!_initialized) {
		__initialize();
	}

	if (__get_gdbus_shared_connection(&conn, G_BUS_TYPE_SYSTEM, ES_TYPE_SYSTEM) < 0) {
		_E("getting gdbus-connetion error");
		ret = ES_R_ERROR;
		goto out_1;
	}

	proxy = g_dbus_proxy_new_sync(conn,
		G_DBUS_PROXY_FLAGS_NONE, NULL,
		ESD_BUS_NAME, ESD_OBJECT_PATH, ESD_INTERFACE_NAME,
		NULL, &error);
	if (proxy == NULL) {
		_E("failed to create new proxy, error(%s)", error->message);
		g_error_free(error);
		ret = ES_R_ERROR;
		goto out_1;
	}

	param = g_variant_new("(s)", event_name);

	value = g_dbus_proxy_call_sync(proxy, "GetTrustedPeerList", param,
		G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (error != NULL) {
		_E("proxy call sync error(%s)", error->message);
		g_error_free(error);
		ret = ES_R_ERROR;
		goto out_2;
	}

	g_variant_get(value, "(ias)", &result, &iter);

	_D("result(%d)", result);

	if (result == 1) {
		ret = ES_R_OK;
		while (g_variant_iter_loop(iter, "s", &str)) {
			dest_name = strdup((char *)str);
			if (dest_name) {
				_D("dest name(%s)", str);
				*dest_list = g_list_append(*dest_list, dest_name);
			} else {
				_E("out of memory");
				ret = ES_R_ENOMEM;
				break;
			}
		}
	}
	g_variant_iter_free(iter);

out_2:
	g_variant_unref(value);
out_1:
	if (conn) {
		g_object_unref(conn);
	}

	return ret;
}

#ifdef APPFW_EVENT_SYSTEM_EARLIER_FEATURE
static int __eventsystem_request_earlier_data(const char *event_name,
		eventsystem_cb callback, void *user_data)
{
	int ret = 0;
	GDBusConnection *conn = NULL;
	GError *error = NULL;
	GDBusProxy *proxy = NULL;
	GVariant *param = NULL;
	gint result = 0;
	bundle_raw *raw = NULL;
	int len = 0;

	if (!_initialized) {
		__initialize();
	}

	if (__get_gdbus_shared_connection(&conn, G_BUS_TYPE_SYSTEM, ES_TYPE_SYSTEM) < 0) {
		_E("getting gdbus-connetion error");
		ret = ES_R_ERROR;
		goto out_1;
	}

	proxy = g_dbus_proxy_new_sync(conn,
		G_DBUS_PROXY_FLAGS_NONE, NULL,
		ESD_BUS_NAME, ESD_OBJECT_PATH, ESD_INTERFACE_NAME,
		NULL, &error);

	if (proxy == NULL) {
		_E("failed to create new proxy, error(%s)", error->message);
		g_error_free(error);
		ret = ES_R_ERROR;
		goto out_1;
	}

	param = g_variant_new("(s)", event_name);
	GVariant *value = g_dbus_proxy_call_sync(proxy, "GetEarlierData", param,
		G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (error != NULL) {
		_E("proxy call sync error(%s)", error->message);
		g_error_free(error);
		ret = ES_R_ERROR;
		goto out_2;
	}

	g_variant_get(value, "(iis)", &result, &len, &raw);
	g_variant_unref(value);

	_D("result(%d), len(%d)", result, len);

	if (!result && raw && len > 0) {
		callback(event_name, raw, len, user_data);
		bundle_free_encoded_rawdata(&raw);
	}

	ret = ES_R_OK;

out_2:
	g_variant_unref(value);
out_1:
	if (conn) {
		g_object_unref(conn);
	}

	return ret;
}
#endif

int eventsystem_register_application_event(const char *event_name, unsigned int *reg_id,
		int *event_type, eventsystem_cb callback, void *user_data)
{
	eventmap_s *em;
	char *interface_name = NULL;
	char *object_path = NULL;
	char *member_name = NULL;
	char *sender_name = NULL;
	GDBusSignalCallback filter;
	GBusType bus_type;
	guint  subscription_id  = 0;
	int ret = 0;
	GDBusConnection *conn = NULL;

	if (!_initialized) {
		__initialize();
	}

	if (__check_eventname_validation_system((char *)event_name)) {
		if (__eventsystem_check_privilege_validation(event_name) != ES_R_OK) {
			_E("invalid privilege(%s)", event_name);
			return ES_R_ENOTPERMITTED;
		}
		*event_type = ES_TYPE_SYSTEM;
	} else if (__check_eventname_validation_user((char *)event_name)) {
		*event_type = ES_TYPE_USER;
	} else {
		*event_type = ES_TYPE_UNKNOWN;
		_E("unknown type event(%s)", event_name);
		return ES_R_EINVAL;
	}

	if (*event_type == ES_TYPE_SYSTEM) {
		interface_name = strdup(SYS_EVENT_NAME_PREFIX);
		if (interface_name == NULL) {
			_E("out of memory");
			return ES_R_ENOMEM;
		}
		if (!g_dbus_is_interface_name(interface_name)) {
			_E("invalid interface_name(%s)", interface_name);
			FREE_AND_NULL(interface_name);
			return ES_R_EINVAL;
		}
		member_name = __get_member_name_from_eventname((char *)event_name);
		if (member_name == NULL) {
			_E("member_name is NULL(%s)", event_name);
			FREE_AND_NULL(interface_name);
			return ES_R_ERROR;
		}
		if (!g_dbus_is_member_name(member_name)) {
			_E("Invalid member_name(%s)", member_name);
			FREE_AND_NULL(interface_name);
			FREE_AND_NULL(member_name);
			return ES_R_ERROR;
		}
		filter = __eventsystem_filter_sysevent_for_application;
		bus_type = G_BUS_TYPE_SYSTEM;
	} else {
		interface_name = __get_encoded_interface_name((char *)event_name);
		if (!interface_name) {
			_E("interface_name is NULL");
			return ES_R_ERROR;
		}
		if (!g_dbus_is_interface_name(interface_name)) {
			_E("invalid interface_name(%s)", interface_name);
			FREE_AND_NULL(interface_name);
			return ES_R_EINVAL;
		}
		member_name = strdup(EVENT_SYSTEM_MEMBER);
		if (!member_name) {
			_E("out_of_memory");
			FREE_AND_NULL(interface_name);
			return ES_R_ERROR;
		}
		filter = __eventsystem_filter_userevent_for_application;
		bus_type = G_BUS_TYPE_SESSION;
	}

	object_path = __get_object_path(interface_name);
	if (!object_path) {
		_E("failed get object_path");
		FREE_AND_NULL(interface_name);
		FREE_AND_NULL(member_name);
		return ES_R_ERROR;
	}
	sender_name = NULL;

	_D("interface_name(%s), object_path(%s)", interface_name, object_path);
	_D(" member_name(%s), sender_name(%s), type(%d), bus_type(%d)",
		member_name, sender_name, *event_type, bus_type);

	if (__get_gdbus_shared_connection(&conn, bus_type, *event_type) < 0) {
		_E("getting gdbus-connetion error");
		FREE_AND_NULL(interface_name);
		FREE_AND_NULL(object_path);
		FREE_AND_NULL(member_name);
		return ES_R_ERROR;
	}

#ifdef APPFW_EVENT_SYSTEM_EARLIER_FEATURE
	__eventsystem_request_earlier_data(event_name, callback, user_data);
#endif

	subscription_id = g_dbus_connection_signal_subscribe(conn,
		sender_name, /* sender */
		interface_name,
		member_name, /* member */
		object_path, /* object_path */
		NULL, /* arg0 */
		G_DBUS_SIGNAL_FLAGS_NONE,
		filter,
		user_data,
		NULL); /* user_data_free_func */

	_D("event_name(%s), subscription_id(%d)", event_name, subscription_id);

	if (subscription_id != 0) {
		em = calloc(1, sizeof(eventmap_s));
		if (!em) {
			_E("memory alloc failed");
			ret = ES_R_ENOMEM;
		} else {
			em->interface_name = strdup(interface_name);
			em->member_name = strdup(member_name);
			em->event_name = strdup(event_name);
			em->es_cb = callback;
			em->bus_type = bus_type;
			em->reg_id = subscription_id;
			em->event_type = *event_type;

			if (!em->interface_name || !em->member_name ||
				!em->event_name) {
				_E("out_of_memory");
				FREE_AND_NULL(em->interface_name);
				FREE_AND_NULL(em->member_name);
				FREE_AND_NULL(em->event_name);
				FREE_AND_NULL(em);
				ret = ES_R_ENOMEM;
			} else {
				system_event_list =
					g_list_append(system_event_list, em);
				*reg_id = subscription_id;

				ret = ES_R_OK;

				if (em->bus_type == G_BUS_TYPE_SESSION &&
					 em->event_type == ES_TYPE_USER) {
					if (s_info.own_name_session_bus == NULL) {
						_E("session bus is not ready");
						ret = ES_R_ERROR;
					} else {
						if (__eventsystem_setup_trusted_peer(event_name,
							s_info.own_name_session_bus) < 0) {
							_E("failed to setup trusted peer");
							ret = ES_R_ERROR;
						}
					}
				}
			}
		}
	} else {
		_E("dbus subscribe: error(%d)", subscription_id);
		ret = ES_R_ERROR;
	}

	FREE_AND_NULL(interface_name);
	FREE_AND_NULL(object_path);
	FREE_AND_NULL(member_name);
	if (conn) {
		g_object_unref(conn);
	}

	return ret;
}

int eventsystem_unregister_application_event(unsigned int reg_id)
{
	eventmap_s em;
	eventmap_s *em_data = NULL;
	GBusType bus_type;
	GList *cb_list = NULL;
	GDBusConnection *conn = NULL;
	eventsystem_event_type evt_type;

	retvm_if(reg_id == 0, ES_R_EINVAL, "Invalid argument : reg_id");

	if (!_initialized) {
		__initialize();
	}

	em.reg_id = reg_id;
	cb_list = g_list_find_custom(system_event_list, &em,
		(GCompareFunc)__event_compare_reg_id_cb);
	if (cb_list) {
		em_data = (eventmap_s *)cb_list->data;

		bus_type = em_data->bus_type;
		evt_type = em_data->event_type;

		_D("unsubscribe: reg_id(%d), bus_type(%d)", reg_id, bus_type);

		if (__get_gdbus_shared_connection(&conn, bus_type, evt_type) < 0) {
			_E("getting gdbus-connetion error");
			return ES_R_ERROR;
		}
		g_dbus_connection_signal_unsubscribe(conn, reg_id);

		system_event_list = g_list_remove(system_event_list, cb_list->data);

		FREE_AND_NULL(em_data->interface_name);
		FREE_AND_NULL(em_data->member_name);
		FREE_AND_NULL(em_data->event_name);
		FREE_AND_NULL(em_data);
		g_object_unref(conn);
	} else {
		_E("not found matched item");
		return ES_R_ERROR;
	}

	return ES_R_OK;
}

int eventsystem_application_finalize(void)
{
	gpointer key, value;

	_D("release all resouces");

	if (system_event_list) {
		g_list_free(system_event_list);
	}

	if (check_tbl) {
		GHashTableIter iter;

		g_hash_table_iter_init(&iter, check_tbl);

		while (g_hash_table_iter_next(&iter, &key, &value)) {
			char *val_item = (char *)value;
			if (val_item) {
				free(val_item);
			} else {
				_E("check_tbl, val_item is NULL");
			}
			g_hash_table_iter_remove(&iter);
		}
		g_hash_table_unref(check_tbl);
	}

	if (filter_tbl) {
		GHashTableIter iter;

		g_hash_table_iter_init(&iter, filter_tbl);

		while (g_hash_table_iter_next(&iter, &key, &value)) {
			char *key_item = (char *)key;
			if (key_item) {
				free(key_item);
			} else {
				_E("filter_tbl, key_item is NULL");
			}
			char *val_item = (char *)value;
			if (val_item) {
				free(val_item);
			} else {
				_E("filter_tbl, val_item is NULL");
			}
			g_hash_table_iter_remove(&iter);
		}
		g_hash_table_unref(filter_tbl);
	}

	FREE_AND_NULL(s_info.own_name_system_bus);
	FREE_AND_NULL(s_info.own_name_session_bus);

	return 0;
}
