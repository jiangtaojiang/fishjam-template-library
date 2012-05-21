#ifndef FTL_CRACK_HPP
#define FTL_CRACK_HPP
#pragma once

#ifdef USE_EXPORT
#  include "ftlCrack.h"
#endif


namespace FTL
{
    LPCTSTR CFCrackUtility::s_csKiloString = 
        _T("\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30")  //0x0010(16)	0
        _T("\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31")  //0x0020(32)	1
        _T("\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32")	//0x0030(48)	2	
        _T("\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33")	//0x0040(64)	3
        _T("\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34")	//0x0050(80)	4
        _T("\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35\x35")	//0x0060(96)	5
        _T("\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36")	//0x0070(112)	6
        _T("\x37\x37\x37\x37\x37\x37\x37\x37\x37\x37\x37\x37\x37\x37\x37\x37")	//0x0080(128)	7
        _T("\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38")	//0x0090(144)	8
        _T("\x39\x39\x39\x39\x39\x39\x39\x39\x39\x39\x39\x39\x39\x39\x39\x39")	//0x00a0(160)	9
        _T("\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41")	//0x00b0(176)	A
        _T("\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42")	//0x00c0(192)	B
        _T("\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43")	//0x00d0(208)	C
        _T("\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44")	//0x00e0(224)	D
        _T("\x45\x45\x45\x45\x45\x45\x45\x45\x45\x45\x45\x45\x45\x45\x45\x45")	//0x00f0(240)	E
        _T("\x46\x46\x46\x46\x46\x46\x46\x46\x46\x46\x46\x46\x46\x46\x46\x46")	//0x0100(256)	F

        _T("\x47\x47\x47\x47\x47\x47\x47\x47\x47\x47\x47\x47\x47\x47\x47\x47")	//0x0110(272)	G
        _T("\x48\x48\x48\x48\x48\x48\x48\x48\x48\x48\x48\x48\x48\x48\x48\x48")	//0x0120(288)	H
        _T("\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49")	//0x0130(304)	I
        _T("\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a")	//0x0140(320)	J
        _T("\x4b\x4b\x4b\x4b\x4b\x4b\x4b\x4b\x4b\x4b\x4b\x4b\x4b\x4b\x4b\x4b")	//0x0150(336)	K
        _T("\x4c\x4c\x4c\x4c\x4c\x4c\x4c\x4c\x4c\x4c\x4c\x4c\x4c\x4c\x4c\x4c")	//0x0160(352)	L
        _T("\x4d\x4d\x4d\x4d\x4d\x4d\x4d\x4d\x4d\x4d\x4d\x4d\x4d\x4d\x4d\x4d")	//0x0170(368)	M
        _T("\x4e\x4e\x4e\x4e\x4e\x4e\x4e\x4e\x4e\x4e\x4e\x4e\x4e\x4e\x4e\x4e")	//0x0180(384)	N
        _T("\x4f\x4f\x4f\x4f\x4f\x4f\x4f\x4f\x4f\x4f\x4f\x4f\x4f\x4f\x4f\x4f")	//0x0190(400)	O
        _T("\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50")	//0x01a0(416)	P
        _T("\x51\x51\x51\x51\x51\x51\x51\x51\x51\x51\x51\x51\x51\x51\x51\x51")	//0x01b0(432)	Q
        _T("\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52")	//0x01c0(448)	R
        _T("\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53")	//0x01d0(464)	S
        _T("\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54")	//0x01e0(480)	T
        _T("\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55")	//0x01f0(496)	U
        _T("\x56\x56\x56\x56\x56\x56\x56\x56\x56\x56\x56\x56\x56\x56\x56\x56")	//0x0200(512)	V

        _T("\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57")	//0x0210(528)	W
        _T("\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58\x58")	//0x0220(544)	X
        _T("\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59")	//0x0230(560)	Y
        _T("\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a")	//0x0240(576)	Z
        _T("\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61")	//0x0250(592)	a
        _T("\x62\x62\x62\x62\x62\x62\x62\x62\x62\x62\x62\x62\x62\x62\x62\x62")	//0x0260(608)	b
        _T("\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63")	//0x0270(624)	c
        _T("\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64")	//0x0280(640)	d
        _T("\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65")	//0x0290(656)	e
        _T("\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66")	//0x02a0(672)	f
        _T("\x67\x67\x67\x67\x67\x67\x67\x67\x67\x67\x67\x67\x67\x67\x67\x67")	//0x02b0(688)	g
        _T("\x68\x68\x68\x68\x68\x68\x68\x68\x68\x68\x68\x68\x68\x68\x68\x68")	//0x02c0(704)	h
        _T("\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69")	//0x02d0(720)	i
        _T("\x6a\x6a\x6a\x6a\x6a\x6a\x6a\x6a\x6a\x6a\x6a\x6a\x6a\x6a\x6a\x6a")	//0x02e0(736)	j
        _T("\x6b\x6b\x6b\x6b\x6b\x6b\x6b\x6b\x6b\x6b\x6b\x6b\x6b\x6b\x6b\x6b")	//0x02f0(752)	k
        _T("\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c")	//0x0300(768)	l

        _T("\x6d\x6d\x6d\x6d\x6d\x6d\x6d\x6d\x6d\x6d\x6d\x6d\x6d\x6d\x6d\x6d")	//0x0310(784)	m
        _T("\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e")	//0x0320(800)	n
        _T("\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f")	//0x0330(816)	o
        _T("\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70")	//0x0340(832)	p
        _T("\x71\x71\x71\x71\x71\x71\x71\x71\x71\x71\x71\x71\x71\x71\x71\x71")	//0x0350(848)	q
        _T("\x72\x72\x72\x72\x72\x72\x72\x72\x72\x72\x72\x72\x72\x72\x72\x72")	//0x0360(864)	r
        _T("\x73\x73\x73\x73\x73\x73\x73\x73\x73\x73\x73\x73\x73\x73\x73\x73")	//0x0370(880)	s
        _T("\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74")	//0x0380(896)	t
        _T("\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75")	//0x0390(912)	u
        _T("\x76\x76\x76\x76\x76\x76\x76\x76\x76\x76\x76\x76\x76\x76\x76\x76")	//0x03a0(928)	v
        _T("\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77")	//0x03b0(944)	w
        _T("\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78")	//0x03c0(960)	x
        _T("\x79\x79\x79\x79\x79\x79\x79\x79\x79\x79\x79\x79\x79\x79\x79\x79")	//0x03d0(976)	y
        _T("\x7a\x7a\x7a\x7a\x7a\x7a\x7a\x7a\x7a\x7a\x7a\x7a\x7a\x7a\x7a\x7a")	//0x03e0(992)	z
        _T("\x21\x21\x21\x21\x21\x21\x21\x21\x21\x21\x21\x21\x21\x21\x21\x21")	//0x03e0(1008)	!
        _T("\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22");	//0x03e0(1024)	"


    LPCTSTR CFCrackUtility::s_csPlaceString =
        _T("\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50");

    CFCrackUtility::CFCrackUtility()
    {
        m_pszCrackString = NULL;
    }

    CFCrackUtility::~CFCrackUtility()
    {
        SAFE_DELETE_ARRAY(m_pszCrackString);
    }

    LPCTSTR CFCrackUtility::GetCrackString(CrackStringType csType,DWORD dwPlaceStart /* = 0 */)
    {
        int kiloStringLen = _tcslen(s_csKiloString) + 1;
        HRESULT hr = E_FAIL;

        if (NULL == m_pszCrackString)
        {
            m_pszCrackString = new TCHAR[kiloStringLen];
        }
        ZeroMemory(m_pszCrackString, sizeof(TCHAR) * kiloStringLen);

        switch(csType)
        {
        case csKiloString:
            COM_VERIFY(StringCchCopy(m_pszCrackString,kiloStringLen, s_csKiloString));
            break;
        default:
            FTLASSERT(FALSE);
            break;
        }

        int placeBufLen = _tcslen(s_csPlaceString) * sizeof(TCHAR);
        FTLASSERT(dwPlaceStart >= 0 && dwPlaceStart < kiloStringLen - placeBufLen/sizeof(TCHAR) );
        if (dwPlaceStart > 0 && dwPlaceStart < kiloStringLen - placeBufLen/sizeof(TCHAR))
        {
            CopyMemory(m_pszCrackString + dwPlaceStart, s_csPlaceString, placeBufLen);
        }
        return m_pszCrackString;
    }
}

#endif //FTL_CRACK_HPP