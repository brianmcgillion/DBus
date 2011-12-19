/* smack.c - Provide interface to query smack context
 *
 * Author: Brian McGillion <brian.mcgillion@intel.com>
 * Copyright © 2011 Intel Corporation
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <config.h>
#include "smack.h"

#include <dbus/dbus-internals.h>

#include "connection.h"
#include "services.h"
#include "utils.h"

#ifdef DBUS_ENABLE_SMACK
#include <sys/smack.h>
#endif

#ifdef DBUS_ENABLE_SMACK
static char *
bus_smack_get_label (DBusConnection *connection)
{
  char *label;
  int sock_fd;

  if (!dbus_connection_get_socket(connection, &sock_fd))
    return NULL;

  if (smack_new_label_from_socket(sock_fd, &label) < 0)
    return NULL;
  return label;
}
#endif

dbus_bool_t
bus_smack_handle_get_connection_context (DBusConnection *connection,
                                         BusTransaction *transaction,
                                         DBusMessage    *message,
                                         DBusError      *error)
{
#ifdef DBUS_ENABLE_SMACK
  const char *remote_end = NULL;
  BusRegistry *registry;
  DBusString remote_end_str;
  BusService *service;
  DBusConnection *remote_connection;
  DBusMessage *reply = NULL;
  char *label;

  _DBUS_ASSERT_ERROR_IS_CLEAR (error);

  registry = bus_connection_get_registry (connection);

  if (!dbus_message_get_args (message, error, DBUS_TYPE_STRING, &remote_end,
                              DBUS_TYPE_INVALID))
    return FALSE;

  _dbus_verbose ("asked for label of connection %s\n", remote_end);

  _dbus_string_init_const (&remote_end_str, remote_end);

  service = bus_registry_lookup (registry, &remote_end_str);
  if (service == NULL)
    {
      dbus_set_error (error, DBUS_ERROR_NAME_HAS_NO_OWNER,
                      "Bus name '%s' has no owner", remote_end);
      return FALSE;
    }

  remote_connection = bus_service_get_primary_owners_connection (service);
  if (remote_connection == NULL)
    goto oom;

  reply = dbus_message_new_method_return (message);
  if (reply == NULL)
    goto oom;

  label = bus_smack_get_label (remote_connection);
  if (label == NULL)
    {
      dbus_set_error (error, DBUS_ERROR_FAILED,
                      "Failed to get the socket fd of the connection",
                      remote_end);
      goto err;
    }

  if (!dbus_message_append_args (reply, DBUS_TYPE_STRING,
                                 &label, DBUS_TYPE_INVALID))
    goto oom;

  if (!bus_transaction_send_from_driver (transaction, connection, reply))
    goto oom;

  dbus_message_unref (reply);
  dbus_free(label);

  return TRUE;

oom:
  BUS_SET_OOM (error);

err:
  if (reply != NULL)
    dbus_message_unref (reply);

  dbus_free(label);

  return FALSE;
#else
  dbus_set_error (error, DBUS_ERROR_NOT_SUPPORTED,
                  "SMACK support is not enabled");
  return FALSE;
#endif
}
