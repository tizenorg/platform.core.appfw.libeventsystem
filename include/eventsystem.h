/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __EVENT_SYSTEM_H__
#define __EVENT_SYSTEM_H__

/**
 * header file for eventsystem
 */

#include <stdbool.h>
#include <eventsystem_internal.h>
#include <bundle_internal.h>

#ifdef __cplusplus
extern "C" {
#endif

#define APPFW_EVENT_SYSTEM_EARLIER_FEATURE

typedef enum _eventsystem_return_val {
	ES_R_ENOTPERMITTED = -4,	/* Not permitted */
	ES_R_ENOMEM = -3,		/* Memory allocation error */
	ES_R_EINVAL = -2,		/* Invalid argument */
	ES_R_ERROR = -1,		/* General error */
	ES_R_OK = 0,			/* General success */
	ES_R_REMOVE = 1			/* Neet to remove something */
} eventsystem_return_val;

typedef enum _eventsystem_event_type {
	ES_TYPE_UNKNOWN = 0,	/* unknown event */
	ES_TYPE_USER,		/* user event */
	ES_TYPE_SYSTEM		/* system event */
} eventsystem_event_type;

#define FREE_AND_NULL(ptr) do { \
	if (ptr) { \
		free((void *)ptr); \
		ptr = NULL; \
	} \
} while (0)


/**
 * APIs for Application Framework.
 */

/**
 * interface : Callback for app core
 */
typedef void (*eventsystem_cb)(const char *event_name, bundle_raw *event_data,
		int len, void *user_data);

/**
 * function : Send the user-event
 */
API int eventsystem_send_user_event(const char *event_name, bundle *data, bool is_trusted);

/**
 * function : Register the event of the application
 */
API int eventsystem_register_application_event(const char *event_name, unsigned int *reg_id,
		int *event_type, eventsystem_cb callback, void *user_data);

/**
 * function : Unregister the event of the application
 */
API int eventsystem_unregister_application_event(unsigned int reg_id);

/**
 *function : Finalizer for releasing all resources
 */
API int eventsystem_application_finalize(void);


/**
 * APIs for Internal-Use (daemon or privileged app for sending system-event)
 */

/**
 * interface : Callback for internal use
 *
 * example :
#include <eventsystem.h>
#include <bundle.h>
void battery_level_event_handler(const char *event_name, bundle *data, void *user_data)
{
	const char *batt_level_status = NULL;
	_I("battery event(%s) received", event_name);

	batt_level_status = bundle_get_val(data, EVT_KEY_BATTERY_LEVEL_STATUS);
	_I("batt_level_status(%s)", batt_level_status);
}
 *
 */

typedef void (*eventsystem_handler)(const char *event_name, bundle *data, void *user_data);

/**
 * function : Register the event
 *
 * example :
#include <eventsystem.h>
static void init_func(void *user_data)
{
	int ret = 0;
	ret = eventsystem_register_event(SYS_EVENT_BATTERY_LEVEL_STATUS,
		&batt_level_reg_id,
		(eventsystem_handler)battery_level_event_handler,
		user_data);
	if (ret != ES_R_OK) {
		printf("error");
	}
}
 *
 */
API int eventsystem_register_event(const char *event_name, unsigned int *reg_id,
		eventsystem_handler callback, void *user_data);

/**
 * function : Unregister the event
 *
 * example :
static void exit_func(void *data)
{
	int ret = 0;
	ret = eventsystem_unregister_event(batt_level_reg_id);
	if (ret != ES_R_OK) {
		printf("error");
	}
}
 *
 */
API int eventsystem_unregister_event(unsigned int reg_id);

/**
 * function : Send the system-event
 *
 * example :
static void send_func(void *user_data)
{
	bundle *b = NULL;
	b = bundle_create();
	bundle_add_str(b, EVT_KEY_BATTERY_LEVEL_STATUS, EVT_VAL_BATTERY_LEVEL_HIGH);
	eventsystem_send_system_event(SYS_EVENT_BATTERY_LEVEL_STATUS, b);
	bundle_free(b);
}
 *
 */
API int eventsystem_send_system_event(const char *event_name, bundle *data);

/**
 * function : Request sending the event
 * note : This API is only for privileged application which can not use eventsystem_send_system_event() API because of dbus policy. This API need a privilege.
 * example : similar to event_send_system_event().
 *
 */
API int eventsystem_request_sending_system_event(const char *event_name, bundle *data);


#ifdef __cplusplus
}
#endif

#endif /* __EVENT_SYSTEM_H__ */
