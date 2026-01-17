// urfd -- The universal reflector
// Copyright © 2023 Thomas A. Early N7TAE
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include "Reflector.h"
#include "GateKeeper.h"
#include "Configure.h"
#include "Version.h"
#include "LookupDmr.h"
#include "LookupNxdn.h"
#include "LookupYsf.h"
#include "TCSocket.h"
#include "JsonKeys.h"
#include "NNGPublisher.h"

extern CReflector  g_Reflector;
extern CGateKeeper g_GateKeeper;
extern CConfigure  g_Configure;
extern CVersion    g_Version;
extern CLookupDmr  g_LDid;
extern CLookupNxdn g_LNid;
extern CLookupYsf  g_LYtr;
extern SJsonKeys   g_Keys;
extern CTCServer   g_TCServer;
extern CNNGPublisher g_NNGPublisher;
