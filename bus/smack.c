/* smack.c - Provide interface to query smack context
 *
 * Author: Brian McGillion <brian.mcgillion@intel.com>
 * Copyright © 2012 Intel Corporation
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

#include <stdlib.h>

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef DBUS_ENABLE_SMACK
#include <sys/smack.h>
#endif

char *
bus_smack_get_label (DBusConnection *connection, DBusError *error)
{
#ifdef DBUS_ENABLE_SMACK
  char *label;
  int sock_fd;

  if (!dbus_connection_get_socket(connection, &sock_fd))
    {
      dbus_set_error (error, DBUS_ERROR_FAILED,
                      "Failed to get the socket descriptor of the connection.\n");
      _dbus_verbose ("Failed to get socket descriptor of connection for Smack check.%s\n");
      return NULL;
    }

  /* retrieve an ascii, null-terminated string that defines the Smack context of the connected socket */
  if (smack_new_label_from_socket(sock_fd, &label) < 0)
    {
      dbus_set_error (error, DBUS_ERROR_FAILED,
                      "Failed to read the Smack context from the connection: %s.\n",
                      _dbus_strerror (errno));
      _dbus_verbose ("Failed to read the Smack context from the connection: %s.\n",
                     _dbus_strerror (errno));
      return NULL;
    }
  return label;
#else
  return NULL;
#endif
}

void
bus_smack_label_free (char *label)
{
  if (label)
    free (label);
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
 * @param allowed_list the list of permitted rules if it exists, otherwise NULL.
 * @returns TRUE on success, False otherwise.
 */
dbus_bool_t
bus_smack_generate_allowed_list (DBusConnection *connection,
                                 DBusHashTable  *rules_by_smack_label,
                                 DBusList **allowed_list)
{
#ifdef DBUS_ENABLE_SMACK
  const char *subject_label;
  DBusHashIter iter;
  dbus_bool_t is_allowed;
  DBusList *rule_list;

  /* the label of the subject, is the label on the new connection,
     either the service itself or one of its clients */
  subject_label = bus_connection_get_smack_label (connection);
  if (subject_label == NULL)
    return NULL;

  rule_list = dbus_new0 (DBusList*, 1);
  if (rule_list == NULL)
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

      for (link = _dbus_list_get_first_link (list);
           link != NULL;
           link = _dbus_list_get_next_link (list, link))
        {
          BusPolicyRule *rule = link->data;
          is_allowed = FALSE;

          switch (rule->type)
            {
            case BUS_POLICY_RULE_OWN:
              is_allowed = bus_smack_has_access (subject_label,
                                                 object_label,
                                                 "RWX");
              break;
            case BUS_POLICY_RULE_SEND:
              is_allowed = bus_smack_has_access (subject_label,
                                                 object_label,
                                                 "W");
              break;
            case BUS_POLICY_RULE_RECEIVE:
              is_allowed = bus_smack_has_access (subject_label,
                                                 object_label,
                                                 "R");
              break;
            default:
              continue;
            }

          if (is_allowed)
            {
              if (!_dbus_list_append (rule_list, rule))
                goto nomem;

              bus_policy_rule_ref (rule);
            }

          _dbus_verbose ("permission request subject (%s) -> object (%s) : %s", subject_label, object_label, (is_allowed ? "GRANTED" : "REJECTED"));
        }
    }

  *allowed_list = rule_list;
  return TRUE;

nomem:
  if (rule_list != NULL)
    {
      _dbus_list_clear (&rule_list);
      dbus_free (rule_list);
    }
  return FALSE;
#else
  return TRUE;
#endif
}
