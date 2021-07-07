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
#include "StrUtils.h"
#include "BuffSock.h"

#define BSOCK_EOF                   INT_MIN
#define BSOCK_STD_BUFFER_SIZE       1024

#define BSOCK_NAME(p) (*(p)->IOops.pName)((p)->IOops.pPrivate)
#define BSOCK_FREE(p) (*(p)->IOops.pFree)((p)->IOops.pPrivate)
#define BSOCK_READ(p, d, n, t) (*(p)->IOops.pRead)((p)->IOops.pPrivate, d, n, t)
#define BSOCK_WRITE(p, d, n, t) (*(p)->IOops.pWrite)((p)->IOops.pPrivate, d, n, t)
#define BSOCK_SENDFILE(p, f, b, e, t) (*(p)->IOops.pSendFile)((p)->IOops.pPrivate, f, b, e, t)


struct BuffSocketData {
	SYS_SOCKET SockFD;
	int iBufferSize;
	char *pszBuffer;
	size_t sBytesInBuffer;
	ssize_t sReadIndex;
	BufSockIOOps IOops;
};


static ssize_t BSckReadLL(BuffSocketData *pBSD, void *pData, size_t sSize, int iTimeout)
{
	ssize_t sCount = 0;

	while (sCount < sSize) {
		ssize_t iCRead = BSOCK_READ(pBSD, (char *) pData + sCount,
					    sSize - sCount, iTimeout);
		if (iCRead <= 0)
			return sCount;
		sCount += iCRead;
	}

	return sCount;
}

static ssize_t BSckWriteLL(BuffSocketData *pBSD, void const *pData, size_t sSize, int iTimeout)
{
	ssize_t sCount = 0;

	while (sCount < sSize) {
		ssize_t sCWrite = BSOCK_WRITE(pBSD, (char const *) pData + sCount,
					      sSize - sCount, iTimeout);
		if (sCWrite <= 0)
			return sCount;
		sCount += sCWrite;
	}

	return sCount;
}

static char const *BSckSock_Name(void *pPrivate)
{
	return BSOCK_BIO_NAME;
}

static int BSckSock_Free(void *pPrivate)
{
	return 0;
}

static ssize_t BSckSock_Read(void *pPrivate, void *pData, size_t sSize, int iTimeout)
{
	return SysRecvData((SYS_SOCKET) (size_t) pPrivate, (char *) pData, sSize, iTimeout);
}

static ssize_t BSckSock_Write(void *pPrivate, void const *pData, size_t sSize, int iTimeout)
{
	return SysSendData((SYS_SOCKET) (size_t) pPrivate, (char const *) pData, sSize, iTimeout);
}

static int BSckSock_SendFile(void *pPrivate, char const *pszFilePath, SYS_OFF_T llBaseOffset,
			     SYS_OFF_T llEndOffset, int iTimeout)
{
	return SysSendFile((SYS_SOCKET) (size_t) pPrivate, pszFilePath, llBaseOffset,
			   llEndOffset, iTimeout);
}

BSOCK_HANDLE BSckAttach(SYS_SOCKET SockFD, int iBufferSize)
{
	BuffSocketData *pBSD = (BuffSocketData *) SysAlloc(sizeof(BuffSocketData));

	if (pBSD == NULL)
		return INVALID_BSOCK_HANDLE;

	char *pszBuffer = (char *) SysAlloc(iBufferSize);

	if (pszBuffer == NULL) {
		SysFree(pBSD);
		return INVALID_BSOCK_HANDLE;
	}

	pBSD->SockFD = SockFD;
	pBSD->iBufferSize = iBufferSize;
	pBSD->pszBuffer = pszBuffer;
	pBSD->sBytesInBuffer = 0;
	pBSD->sReadIndex = 0;
	pBSD->IOops.pPrivate = (void *) (size_t) SockFD;
	pBSD->IOops.pName = BSckSock_Name;
	pBSD->IOops.pFree = BSckSock_Free;
	pBSD->IOops.pRead = BSckSock_Read;
	pBSD->IOops.pWrite = BSckSock_Write;
	pBSD->IOops.pSendFile = BSckSock_SendFile;

	return (BSOCK_HANDLE) pBSD;
}

SYS_SOCKET BSckDetach(BSOCK_HANDLE hBSock, int iCloseSocket)
{
	BuffSocketData *pBSD = (BuffSocketData *) hBSock;
	SYS_SOCKET SockFD = SYS_INVALID_SOCKET;

	if (pBSD != NULL) {
		SockFD = pBSD->SockFD;
		BSOCK_FREE(pBSD);
		SysFree(pBSD->pszBuffer);
		SysFree(pBSD);
		if (iCloseSocket) {
			SysCloseSocket(SockFD);
			return SYS_INVALID_SOCKET;
		}
	}

	return SockFD;
}

static int BSckFetchData(BuffSocketData *pBSD, int iTimeout)
{
	int iRdBytes;

	pBSD->sReadIndex = 0;
	if ((iRdBytes = BSOCK_READ(pBSD, pBSD->pszBuffer, pBSD->iBufferSize,
				   iTimeout)) <= 0) {
		ErrSetErrorCode(ERR_SOCK_NOMORE_DATA);
		return iRdBytes;
	}
	pBSD->sBytesInBuffer = iRdBytes;

	return iRdBytes;
}

int BSckGetChar(BSOCK_HANDLE hBSock, int iTimeout)
{
	BuffSocketData *pBSD = (BuffSocketData *) hBSock;

	if ((pBSD->sBytesInBuffer == 0) && (BSckFetchData(pBSD, iTimeout) <= 0))
		return BSOCK_EOF;

	int iChar = (int) pBSD->pszBuffer[pBSD->sReadIndex];

	pBSD->sReadIndex = INext(pBSD->sReadIndex, pBSD->iBufferSize);
	--pBSD->sBytesInBuffer;

	return iChar;
}

char *BSckChGetString(BSOCK_HANDLE hBSock, char *pszBuffer, size_t sMaxChars, int iTimeout,
		      size_t *pLineLength, int *piGotNL)
{
	int i, iChar;

	for (i = 0, sMaxChars--; i < sMaxChars; i++) {
		iChar = BSckGetChar(hBSock, iTimeout);
		if (iChar == BSOCK_EOF)
			return NULL;
		if (iChar == '\n') {
			for (; (i > 0) && (pszBuffer[i - 1] == '\r'); i--);
			pszBuffer[i] = '\0';
			if (pLineLength != NULL)
				*pLineLength = i;
			if (piGotNL != NULL)
				*piGotNL = 1;

			return pszBuffer;
		} else
			pszBuffer[i] = (char) iChar;
	}
	pszBuffer[i] = '\0';
	if (pLineLength != NULL)
		*pLineLength = i;
	if (piGotNL != NULL) {
		*piGotNL = 0;
		return pszBuffer;
	}

	ErrSetErrorCode(ERR_LINE_TOO_LONG);

	return NULL;
}

char *BSckGetString(BSOCK_HANDLE hBSock, char *pszBuffer, size_t sMaxChars, int iTimeout,
		    size_t *pLineLength, int *piGotNL)
{
	size_t i;
	BuffSocketData *pBSD = (BuffSocketData *) hBSock;

	for (i = 0, sMaxChars--; i < sMaxChars;) {
		/* Verify to have something to read */
		if (pBSD->sBytesInBuffer == 0 && BSckFetchData(pBSD, iTimeout) <= 0)
			return NULL;

		size_t sBytesLookup = Min(pBSD->sBytesInBuffer, sMaxChars - i);

		if (sBytesLookup > 0) {
			char *pszNL = (char *) memchr(pBSD->pszBuffer + pBSD->sReadIndex, '\n',
						      sBytesLookup);

			if (pszNL != NULL) {
				int iCopySize = (int) (pszNL - (pBSD->pszBuffer + pBSD->sReadIndex));

				memcpy(pszBuffer + i, pBSD->pszBuffer + pBSD->sReadIndex,
				       iCopySize);
				i += iCopySize;
				pBSD->sReadIndex += iCopySize + 1;
				pBSD->sBytesInBuffer -= iCopySize + 1;

				for (; i > 0 && pszBuffer[i - 1] == '\r'; i--);
				pszBuffer[i] = '\0';
				if (pLineLength != NULL)
					*pLineLength = i;
				if (piGotNL != NULL)
					*piGotNL = 1;

				return pszBuffer;
			} else {
				memcpy(pszBuffer + i, pBSD->pszBuffer + pBSD->sReadIndex,
				       sBytesLookup);
				i += sBytesLookup;
				pBSD->sReadIndex += sBytesLookup;
				pBSD->sBytesInBuffer -= sBytesLookup;
			}
		}
	}
	pszBuffer[i] = '\0';
	if (pLineLength != NULL)
		*pLineLength = i;
	if (piGotNL != NULL) {
		*piGotNL = 0;
		return pszBuffer;
	}

	ErrSetErrorCode(ERR_LINE_TOO_LONG);

	return NULL;
}

ssize_t BSckSendString(BSOCK_HANDLE hBSock, char const *pszBuffer, int iTimeout)
{
	BuffSocketData *pBSD = (BuffSocketData *) hBSock;
	char *pszSendBuffer = (char *) SysAlloc(strlen(pszBuffer) + 3);

	if (pszSendBuffer == NULL)
		return ErrGetErrorCode();

	sprintf(pszSendBuffer, "%s\r\n", pszBuffer);

	size_t sSendLength = strlen(pszSendBuffer);

	if (BSckWriteLL(pBSD, pszSendBuffer, sSendLength, iTimeout) != sSendLength) {
		SysFree(pszSendBuffer);
		return ErrGetErrorCode();
	}
	SysFree(pszSendBuffer);

	return sSendLength;
}

int BSckVSendString(BSOCK_HANDLE hBSock, int iTimeout, char const *pszFormat, ...)
{
	char *pszBuffer = NULL;

	StrVSprint(pszBuffer, pszFormat, pszFormat);

	if (pszBuffer == NULL)
		return ErrGetErrorCode();
	if (BSckSendString(hBSock, pszBuffer, iTimeout) < 0) {
		ErrorPush();
		SysFree(pszBuffer);
		return ErrorPop();
	}
	SysFree(pszBuffer);

	return 0;
}

ssize_t BSckSendData(BSOCK_HANDLE hBSock, char const *pszBuffer, size_t sSize, int iTimeout)
{
	BuffSocketData *pBSD = (BuffSocketData *) hBSock;

	if (BSckWriteLL(pBSD, pszBuffer, sSize, iTimeout) != sSize)
		return ErrGetErrorCode();

	return sSize;
}

int BSckReadData(BSOCK_HANDLE hBSock, char *pszBuffer, size_t sSize, int iTimeout, size_t sSizeFill)
{
	BuffSocketData *pBSD = (BuffSocketData *) hBSock;
	size_t sRdBytes = 0, sBufRdBytes = Min(sSize, pBSD->sBytesInBuffer);

	if (sBufRdBytes > 0) {
		memcpy(pszBuffer, pBSD->pszBuffer + pBSD->sReadIndex, sBufRdBytes);
		pBSD->sReadIndex += sBufRdBytes;
		pBSD->sBytesInBuffer -= sBufRdBytes;
		sRdBytes = sBufRdBytes;
	}
	if (sRdBytes == 0 || (sSizeFill && sRdBytes < sSize)) {
		int iRdSize = BSckReadLL(pBSD, pszBuffer + sRdBytes,
					 sSize - sRdBytes, iTimeout);

		if (iRdSize > 0)
			sRdBytes += iRdSize;
	}

	return sRdBytes;
}

int BSckSendFile(BSOCK_HANDLE hBSock, char const *pszFilePath, SYS_OFF_T llBaseOffset,
		 SYS_OFF_T llEndOffset, int iTimeout)
{
	BuffSocketData *pBSD = (BuffSocketData *) hBSock;

	return BSOCK_SENDFILE(pBSD, pszFilePath, llBaseOffset, llEndOffset, iTimeout);
}

SYS_SOCKET BSckGetAttachedSocket(BSOCK_HANDLE hBSock)
{
	BuffSocketData *pBSD = (BuffSocketData *) hBSock;

	return pBSD->SockFD;
}

int BSckSetIOops(BSOCK_HANDLE hBSock, BufSockIOOps const *pIOops)
{
	BuffSocketData *pBSD = (BuffSocketData *) hBSock;

	pBSD->IOops = *pIOops;

	return 0;
}

char const *BSckBioName(BSOCK_HANDLE hBSock)
{
	BuffSocketData *pBSD = (BuffSocketData *) hBSock;

	return BSOCK_NAME(pBSD);
}

int BSckBufferInit(BSockLineBuffer *pBLB, size_t sSize)
{
	if (sSize <= 0)
		sSize = BSOCK_STD_BUFFER_SIZE;
	if ((pBLB->pszBuffer = (char *) SysAlloc(sSize)) == NULL)
		return ErrGetErrorCode();
	pBLB->sSize = sSize;

	return 0;
}

void BSckBufferFree(BSockLineBuffer *pBLB)
{
	SysFree(pBLB->pszBuffer);
}

char *BSckBufferGet(BSOCK_HANDLE hBSock, BSockLineBuffer *pBLB, int iTimeout, size_t *pLnLength)
{
	size_t sLnLength = 0, sCurrLength;
	int iGotNL;

	do {
		if (BSckGetString(hBSock, pBLB->pszBuffer + sLnLength,
				  pBLB->sSize - 1 - sLnLength, iTimeout, &sCurrLength,
				  &iGotNL) == NULL)
			return NULL;
		if (!iGotNL) {
			int iNewSize = 2 * pBLB->sSize + 1;
			char *pszBuffer = (char *) SysRealloc(pBLB->pszBuffer,
							      (unsigned int) iNewSize);

			if (pszBuffer == NULL)
				return NULL;
			pBLB->pszBuffer = pszBuffer;
			pBLB->sSize = iNewSize;
		}
		sLnLength += sCurrLength;
	} while (!iGotNL);
	if (pLnLength != NULL)
		*pLnLength = sLnLength;

	return pBLB->pszBuffer;
}
