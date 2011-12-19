/* smack.h - Provide interface to query smack context
 *
 * Author: Brian McGillion <brian.mcgillion@intel.com>
 * Copyright © 2011 Intel Corporation
 *
 * Based on example from Stats interface
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

#ifndef SMACK_H
#define SMACK_H

#include "bus.h"

dbus_bool_t bus_smack_handle_get_connection_context (DBusConnection *connection,
                                                     BusTransaction *transaction,
                                                     DBusMessage    *message,
                                                     DBusError      *error);

#endif // SMACK_H
