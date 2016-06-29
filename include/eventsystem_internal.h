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

#ifndef __EVENTSYSTEM_INTERNAL_H__
#define ___EVENTSYSTEM_INTERNAL_H__

#ifdef __cplusplus
extern "C" {
#endif

#define ESD_BUS_NAME "tizen.system.event.app2esd"
#define ESD_OBJECT_PATH "/tizen/system/event/app2esd"
#define ESD_INTERFACE_NAME "tizen.system.event.app2esd"

#define USER_EVENT_NAME_PREFIX "event."

#define SYS_EVENT_NAME_PREFIX "tizen.system.event"
#define SYS_EVENT_OBJ_PATH "/tizen/system/event"

/**
 * system-event definitions
 */

/** esd : for checking esd available */
#define SYS_EVENT_ESD_STATUS "tizen.system.event.esd_status"
/* key */
#define EVT_KEY_ESD_STATUS "esd_status"
/* value */
#define EVT_VAL_ESD_STARTED "started"
#define EVT_VAL_ESD_STOPPED "stopped"

/** esd : for sending saved event date request */
#define SYS_EVENT_ESD_KEEP_DATA "tizen.system.event.esd_keep_data"
/* key */
#define EVT_KEY_ESD_KEEP_DATA "esd_status"
/* value */
#define EVT_VAL_ESD_EVENT_NAME "esd_event_name"
#define EVT_VAL_ESD_OWN_NAME "esd_own_name"

/** battery : charger status */
#define SYS_EVENT_BATTERY_CHARGER_STATUS "tizen.system.event.battery_charger_status"
/* key */
#define EVT_KEY_BATTERY_CHARGER_STATUS "battery_charger_status"
/* value */
#define EVT_VAL_BATTERY_CHARGER_DISCONNECTED "disconnected"
#define EVT_VAL_BATTERY_CHARGER_CONNECTED "connected"
#define EVT_VAL_BATTERY_CHARGER_CHARGING "charging"
#define EVT_VAL_BATTERY_CHARGER_DISCHARGING "discharging"

/** battery : level status */
#define SYS_EVENT_BATTERY_LEVEL_STATUS "tizen.system.event.battery_level_status"
/* key */
#define EVT_KEY_BATTERY_LEVEL_STATUS "battery_level_status"
/* value */
#define EVT_VAL_BATTERY_LEVEL_EMPTY "empty"
#define EVT_VAL_BATTERY_LEVEL_CRITICAL "critical"
#define EVT_VAL_BATTERY_LEVEL_LOW "low"
#define EVT_VAL_BATTERY_LEVEL_HIGH "high"
#define EVT_VAL_BATTERY_LEVEL_FULL "full"

/** usb : status of usb connection */
#define SYS_EVENT_USB_STATUS "tizen.system.event.usb_status"
/* key */
#define EVT_KEY_USB_STATUS "usb_status"
/* value */
#define EVT_VAL_USB_DISCONNECTED "disconnected"
#define EVT_VAL_USB_CONNECTED "connected"
#define EVT_VAL_USB_AVAILABLE "available"

/** ear-jack : status of ear-jack connection */
#define SYS_EVENT_EARJACK_STATUS "tizen.system.event.earjack_status"
/* key */
#define EVT_KEY_EARJACK_STATUS "earjack_status"
/* value */
#define EVT_VAL_EARJACK_DISCONNECTED "disconnected"
#define EVT_VAL_EARJACK_CONNECTED "connected"

/** display : state of display */
#define SYS_EVENT_DISPLAY_STATE "tizen.system.event.display_state"
/* key */
#define EVT_KEY_DISPLAY_STATE "display_state"
/* value */
#define EVT_VAL_DISPLAY_NORMAL "normal"
#define EVT_VAL_DISPLAY_DIM "dim"
#define EVT_VAL_DISPLAY_OFF "off"

/** system : boot completion */
#define SYS_EVENT_BOOT_COMPLETED "tizen.system.event.boot_completed"
/* key */
#define EVT_KEY_BOOT_COMPLETED "boot_completed"
/* value */
#define EVT_VAL_BOOT_COMPLETED_TRUE "true"

/** system : shutdown */
#define SYS_EVENT_SYSTEM_SHUTDOWN "tizen.system.event.system_shutdown"
/* key */
#define EVT_KEY_SYSTEM_SHUTDOWN "system_shutdown"
/* value */
#define EVT_VAL_SYSTEM_SHUTDOWN_TRUE "true" /* go to shutdown */

/** resource : low memory */
#define SYS_EVENT_LOW_MEMORY "tizen.system.event.low_memory"
/* key */
#define EVT_KEY_LOW_MEMORY "low_memory"
/* value */
#define EVT_VAL_MEMORY_NORMAL "normal"
#define EVT_VAL_MEMORY_SOFT_WARNING "soft_warning"
#define EVT_VAL_MEMORY_HARD_WARNING "hard_warning"

/** wifi : state of wifi */
#define SYS_EVENT_WIFI_STATE "tizen.system.event.wifi_state"
/* key */
#define EVT_KEY_WIFI_STATE "wifi_state"
/* value */
#define EVT_VAL_WIFI_OFF "off"
#define EVT_VAL_WIFI_ON "on"
#define EVT_VAL_WIFI_CONNECTED "connected"

/** bluetooth : state of bluetooth */
#define SYS_EVENT_BT_STATE "tizen.system.event.bt_state"
/* key */
#define EVT_KEY_BT_STATE "bt_state"
/* value */
#define EVT_VAL_BT_OFF "off"
#define EVT_VAL_BT_ON "on"
/* key */
#define EVT_KEY_BT_LE_STATE "bt_le_state"
/* value */
#define EVT_VAL_BT_LE_OFF "off"
#define EVT_VAL_BT_LE_ON "on"
/* key */
#define EVT_KEY_BT_TRANSFERING_STATE "bt_transfering_state"
/* value */
#define EVT_VAL_BT_NON_TRANSFERING "non_transfering"
#define EVT_VAL_BT_TRANSFERING "transfering"

/** location : enable state of location */
#define SYS_EVENT_LOCATION_ENABLE_STATE "tizen.system.event.location_enable_state"
/* key */
#define EVT_KEY_LOCATION_ENABLE_STATE "location_enable_state"
/* value */
#define EVT_VAL_LOCATION_DISABLED "disabled"
#define EVT_VAL_LOCATION_ENABLED "enabled"

/** location : enable state of gps */
#define SYS_EVENT_GPS_ENABLE_STATE "tizen.system.event.gps_enable_state"
/* key */
#define EVT_KEY_GPS_ENABLE_STATE "gps_enable_state"
/* value */
#define EVT_VAL_GPS_DISABLED "disabled"
#define EVT_VAL_GPS_ENABLED "enabled"

/** location : enable state of nps */
#define SYS_EVENT_NPS_ENABLE_STATE "tizen.system.event.nps_enable_state"
/* key */
#define EVT_KEY_NPS_ENABLE_STATE "nps_enable_state"
/* value */
#define EVT_VAL_NPS_DISABLED "disabled"
#define EVT_VAL_NPS_ENABLED "enabled"

/** message : incoming msg */
#define SYS_EVENT_INCOMMING_MSG "tizen.system.event.incoming_msg"
/* key */
#define EVT_KEY_MSG_TYPE "msg_type"
/* value */
#define EVT_VAL_SMS "sms"
#define EVT_VAL_MMS "mms"
#define EVT_VAL_PUSH "push"
#define EVT_VAL_CB "cb"
/* key */
#define EVT_KEY_MSG_ID "msg_id"
/* value description
 *"{unsigned int value}" : new message id
 */

/** message : outgoing msg */
#define SYS_EVENT_OUTGOING_MSG "tizen.system.event.outgoing_msg"
/* key */
#define EVT_KEY_OUT_MSG_TYPE "msg_type"
/* value */
#define EVT_VAL_OUT_MSG_SMS "sms"
#define EVT_VAL_OUT_MSG_MMS "mms"
/* key */
#define EVT_KEY_OUT_MSG_ID "msg_id"
/* value description
 *"{unsigned int value}" : new message id
 */

/** setting : time changed */
#define SYS_EVENT_TIME_CHANGED "tizen.system.event.time_changed"
/* key */
#define EVT_KEY_TIME_CHANGED "time_changed"
/* value */
/* do not set "false", just set "true" for broadcasting time_changed */
#define EVT_VAL_TIME_CHANGED_TRUE "true"

/** setting : timezone setting */
#define SYS_EVENT_TIME_ZONE "tizen.system.event.time_zone"
/* key */
#define EVT_KEY_TIME_ZONE "time_zone"
/* vlaue description
 * "Asia/Seoul" : tzpaht value
 */

/** setting : hour format */
#define SYS_EVENT_HOUR_FORMAT "tizen.system.event.hour_format"
/* key */
#define EVT_KEY_HOUR_FORMAT "hour_format"
/* value */
#define EVT_VAL_HOURFORMAT_12 "12"
#define EVT_VAL_HOURFORMAT_24 "24"

/** setting : language setting */
#define SYS_EVENT_LANGUAGE_SET "tizen.system.event.language_set"
/* key */
#define EVT_KEY_LANGUAGE_SET "language_set"
/* value description
 * "ko_KR.UTF8" : in case of Korean language
 * "en_US.UTF8" : in case of USA language
 * ...
 */

/** setting : region format */
#define SYS_EVENT_REGION_FORMAT "tizen.system.event.region_format"
/* key */
#define EVT_KEY_REGION_FORMAT "region_format"
/* value description
 * "ko_KR.UTF8" : in case of Korean region format
 * "en_US.UTF8" : in case of USA region format
 * "en_UK.UTF8" : in case of United Kingdom
 * ...
 */

/** setting : silent mode */
#define SYS_EVENT_SILENT_MODE "tizen.system.event.silent_mode"
/* key */
#define EVT_KEY_SILENT_MODE "silent_mode"
/* value */
#define EVT_VAL_SILENTMODE_ON "on"
#define EVT_VAL_SILENTMODE_OFF "off"

/** setting : state of vibration */
#define SYS_EVENT_VIBRATION_STATE "tizen.system.event.vibration_state"
/* key */
#define EVT_KEY_VIBRATION_STATE "vibration_state"
/* value */
#define EVT_VAL_VIBRATION_ON "on"
#define EVT_VAL_VIBRATION_OFF "off"

/** setting : state of screen's auto-rotation */
#define SYS_EVENT_SCREEN_AUTOROTATE_STATE "tizen.system.event.screen_autorotate_state"
/* key */
#define EVT_KEY_SCREEN_AUTOROTATE_STATE "screen_autorotate_state"
/* value */
#define EVT_VAL_SCREEN_AUTOROTATE_ON "on"
#define EVT_VAL_SCREEN_AUTOROTATE_OFF "off"

/** setting : state of mobile data */
#define SYS_EVENT_MOBILE_DATA_STATE "tizen.system.event.mobile_data_state"
/* key */
#define EVT_KEY_MOBILE_DATA_STATE "mobile_data_state"
/* value */
#define EVT_VAL_MOBILE_DATA_OFF "off"
#define EVT_VAL_MOBILE_DATA_ON "on"

/** setting : state of data roaming */
#define SYS_EVENT_DATA_ROAMING_STATE "tizen.system.event.data_roaming_state"
/* key */
#define EVT_KEY_DATA_ROAMING_STATE "data_roaming_state"
/* value */
#define EVT_VAL_DATA_ROAMING_OFF "off"
#define EVT_VAL_DATA_ROAMING_ON "on"

/** setting : font setting */
#define SYS_EVENT_FONT_SET "tizen.system.event.font_set"
/* key */
#define EVT_KEY_FONT_SET "font_set"
/* value description
 * font name of string type by font-config.
 */

/** network : connection type */
#define SYS_EVENT_NETWORK_STATUS "tizen.system.event.network_status"
/* key */
#define EVT_KEY_NETWORK_STATUS "network_status"
/* value */
#define EVT_VAL_NETWORK_DISCONNECTED "disconnected"
#define EVT_VAL_NETWORK_WIFI "wifi"
#define EVT_VAL_NETWORK_CELLULAR "cellular"
#define EVT_VAL_NETWORK_ETHERNET "ethernet"
#define EVT_VAL_NETWORK_BT "bt"
#define EVT_VAL_NETWORK_NET_PROXY "net_proxy"

#ifdef __cplusplus
}
#endif

#endif /* __EVENTSYSTEM_INTERNAL_H__ */
