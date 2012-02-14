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
#include "policy.h"

#ifdef DBUS_ENABLE_SMACK
#include <sys/smack.h>
#endif

#define SMACK_WRITE "W"
#define SMACK_READ "R"
#define SMACK_READ_WRITE "RW"


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

#ifdef DBUS_ENABLE_SMACK
static dbus_bool_t
bus_smack_has_access (const char *subject, const char *object,
                      const char *access)
{
  return (smack_have_access (subject, object, access) == 1 ? TRUE : FALSE);
}
#endif


/**
 * Calculate the list of rules that apply to a connection.
 *
 * @param connection The inbound conenction
 * @param rules_by_smack_label The table of object labels -> rules mapping
 * @param nomem_err (out) If a nomem situation is encountered this value is set to TRUE.
 * @returns the list of permitted rules if it exists and no errors were encountered otherwise NULL.
 */
DBusList**
bus_smack_generate_allowed_list (DBusConnection *connection,
                                 DBusHashTable  *rules_by_smack_label,
                                 dbus_bool_t *nomem_err)
{
#ifdef DBUS_ENABLE_SMACK
  char *subject_label;
  DBusHashIter iter;
  dbus_bool_t is_allowed;
  DBusList **allowed_list;

  /* the label of the subject, is the label on the new connection,
     either the service itself or one of its clients */
  subject_label = bus_smack_get_label (connection);
  if (subject_label == NULL)
    return NULL;

  allowed_list = dbus_new0 (DBusList*, 1);
  if (allowed_list == NULL)
    goto nomem;

  /* Iterate over all the smack labels we have parsed from the .conf files */
  _dbus_hash_iter_init (rules_by_smack_label, &iter);
  while (_dbus_hash_iter_next (&iter))
    {
      DBusList *link;
      const char *object_label = _dbus_hash_iter_get_string_key (&iter);
      /* the list here is all the rules that are 'protected'
         by the SMACK label named $object_label */
      DBusList **list = _dbus_hash_iter_get_value (&iter);

      link = _dbus_list_get_first_link (list);
      while (link != NULL)
        {
          BusPolicyRule *rule = link->data;
          link = _dbus_list_get_next_link (list, link);
          is_allowed = FALSE;

          switch (rule->type)
            {
            case BUS_POLICY_RULE_OWN:
              is_allowed = bus_smack_has_access (subject_label,
                                                 object_label,
                                                 SMACK_READ_WRITE);
              break;
            case BUS_POLICY_RULE_SEND:
              is_allowed = bus_smack_has_access (subject_label,
                                                 object_label,
                                                 SMACK_WRITE);
              break;
            case BUS_POLICY_RULE_RECEIVE:
              is_allowed = bus_smack_has_access (subject_label,
                                                 object_label,
                                                 SMACK_READ);
              break;
            default:
              continue;
            }

          if (is_allowed)
            {
              if (!_dbus_list_append (allowed_list, rule))
                goto nomem;

              bus_policy_rule_ref (rule);
            }

          _dbus_verbose ("permission request subject (%s) -> object (%s) : %s", subject_label, object_label, (is_allowed ? "GRANTED" : "REJECTED"));
        }
    }

  dbus_free(subject_label);
  return allowed_list;

nomem:
  if (allowed_list != NULL)
    _dbus_list_clear (allowed_list);

  dbus_free(subject_label);
  *nomem_err = TRUE;
  return NULL;

#else
  return NULL;
#endif
}
