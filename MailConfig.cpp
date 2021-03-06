/*
 *  XMail by Davide Libenzi (Intranet and Internet mail server)
 *  Copyright (C) 1999,..,2010  Davide Libenzi
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  Davide Libenzi <davidel@xmailserver.org>
 *
 */

#include "SysInclude.h"
#include "SysDep.h"
#include "SvrDefines.h"
#include "ShBlocks.h"
#include "StrUtils.h"
#include "MessQueue.h"
#include "MailSvr.h"
#include "MailConfig.h"

char *CfgGetRootPath(char *pszPath, size_t sMaxPath)
{
	StrNCpy(pszPath, szMailPath, sMaxPath);

	return pszPath;
}

char *CfgGetBasedPath(const char *pszFullPath, char *pszBasePath, size_t sMaxPath)
{
	size_t sRootLength;
	char szRootPath[SYS_MAX_PATH] = "";

	CfgGetRootPath(szRootPath, sizeof(szRootPath));
	sRootLength = strlen(szRootPath);
	if (strncmp(pszFullPath, szRootPath, sRootLength) == 0)
		StrNCpy(pszBasePath, pszFullPath + sRootLength, sMaxPath);
	else
		StrNCpy(pszBasePath, pszFullPath, sMaxPath);

	return pszBasePath;
}

char *CfgGetFullPath(const char *pszRelativePath, char *pszFullPath, size_t sMaxPath)
{
	CfgGetRootPath(pszFullPath, sMaxPath);
	StrNCat(pszFullPath,
		(*pszRelativePath != SYS_SLASH_CHAR) ? pszRelativePath: pszRelativePath + 1,
		sMaxPath);

	return pszFullPath;
}
