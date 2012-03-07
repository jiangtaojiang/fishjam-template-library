///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// @file   ftlComDetect.h
/// @brief  Functional Template Library Base Header File.
/// @author fujie
/// @version 0.6 
/// @date 03/30/2008
/// @defgroup ftlComDetect ftl Com Detect function and class
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef FTL_COM_DETECT_H
#define FTL_COM_DETECT_H
#pragma once

#ifndef FTL_BASE_H
#  error ftlComDetect.h requires ftlbase.h to be included first
#endif

//TODO -- HKLM下的Software\Classes\Interface 下也有接口，似乎不一样？
/**********************************************************************************************************
* 有两种模式查找一个组件支持的接口及数目（QI）
*   1.注册表的 HKEY_CLASSES_ROOT\Interface 目录下有本机上注册的所有接口(包括名字) -- CoDetectInterfaceFromRegister
*     优点：可以随着注册的接口数进行扩展，而且能找到自定义接口；
*     缺点：不能找到本机上没有注册的（如：不能从ActiveX控件中找到 IForegroundTransfer 接口）
*           不能从找到的接口中获取进一步的信息；
*           速度比较慢；
*   2.从自定义的接口列表中查找(CoDetectInterfaceFromList) -- 不能找到接口列表中没有写入的；
*     优点：能自定义需要查找的接口，而且速度快；
*           能从接口中获得进一步的信息 -- 通过 DumpInterfaceInfo 方法
*     缺点：只能从列表中查找，范围较小。而且对不同的编译器需要定义不同的编译条件，并包含不同的头文件
* 
* 自动从 IDL 编译后的 .h 文件中提取出接口的宏(在VS2003下制作) -- 两个文件之间切换，查找并拷贝
* 注意：最好只打开两个文件；禁用  Visual Assist；先激活IDL的头文件，并将光标放在最前面
Option Strict Off
Option Explicit Off
Imports EnvDTE
Imports System.Diagnostics

Public Module RecordingModule
Sub GetInterfaceName()
DTE.ExecuteCommand("Edit.Find")
DTE.Find.FindWhat = "typedef interface "
DTE.Find.Target = vsFindTarget.vsFindTargetCurrentDocument
DTE.Find.MatchCase = True
DTE.Find.MatchWholeWord = False
DTE.Find.Backwards = False
DTE.Find.MatchInHiddenText = False
DTE.Find.PatternSyntax = vsFindPatternSyntax.vsFindPatternSyntaxLiteral
DTE.Find.Action = vsFindAction.vsFindActionFind
DTE.Find.Execute()
DTE.Windows.Item(Constants.vsWindowKindFindReplace).Close()
DTE.ActiveDocument.Selection.CharRight()
DTE.ActiveDocument.Selection.WordRight(True)
DTE.ActiveDocument.Selection.CharLeft(True)
DTE.ActiveDocument.Selection.Copy()
DTE.ExecuteCommand("Window.NextDocumentWindow")
DTE.ActiveDocument.Selection.Text = "DETECT_INTERFACE_ENTRY("
DTE.ActiveDocument.Selection.Paste()
DTE.ActiveDocument.Selection.Text = ")"
DTE.ActiveDocument.Selection.NewLine()
DTE.ExecuteCommand("Window.NextDocumentWindow")
End Sub
End Module
**********************************************************************************************************/


#include <atlconv.h>

namespace FTL
{
    FTLINLINE HRESULT GetInterfaceNameByIID(REFIID rclsid, BSTR * pszName);
}

#ifdef FTL_DEBUG

# define INCLUDE_DETECT_ACTIVSCP    1
# define INCLUDE_DETECT_CONTROL     1
# define INCLUDE_DETECT_DDRAW       0
# define INCLUDE_DETECT_DISPEX      1

#ifndef INCLUDE_DETECT_DTE
#   define INCLUDE_DETECT_DTE       0
#endif 

# define INCLUDE_DETECT_EXDISP      1
# define INCLUDE_DETECT_KSPROXY     0
# define INCLUDE_DETECT_MEDIAOBJ    0
# define INCLUDE_DETECT_MSHTMLC     1
# define INCLUDE_DETECT_MSXML       1
# define INCLUDE_DETECT_OAIDL       1
# define INCLUDE_DETECT_OBJIDL      1
# define INCLUDE_DETECT_OBJSAFE     1
# define INCLUDE_DETECT_OCIDL       1
# define INCLUDE_DETECT_OLEIDL      1
# define INCLUDE_DETECT_QEDIT       0
# define INCLUDE_DETECT_SERVPROV    1
# define INCLUDE_DETECT_SHLOBJ      0
# define INCLUDE_DETECT_STRMIF      0
# define INCLUDE_DETECT_URLMON      1

//Windows Media Format(asf,wma,wmv)
# define INCLUDE_DETECT_WMF         0

# if INCLUDE_DETECT_WMF
#   define INCLUDE_DETECT_DSHOWASF  1
#   define INCLUDE_DETECT_WMSDKIDL  1
# else
#   define INCLUDE_DETECT_DSHOWASF  0
#   define INCLUDE_DETECT_WMSDKIDL  0
# endif

                                      
//#include <initguid.h>

#if INCLUDE_DETECT_ACTIVSCP
#  include <ActivScp.h>
#endif

#if INCLUDE_DETECT_CONTROL
#  include <control.h>
#endif 

#if INCLUDE_DETECT_DDRAW
#  include <ddraw.h>
#endif

#if INCLUDE_DETECT_DISPEX
#  include <DispEx.h>
#endif

#if INCLUDE_DETECT_DSHOWASF
#  include <dshowasf.h>
#endif

#if INCLUDE_DETECT_EXDISP
#  include <exdisp.h>
#endif

#if INCLUDE_DETECT_KSPROXY
#  include <ks.h>
#  include <ksproxy.h>
#endif 

#if INCLUDE_DETECT_MEDIAOBJ
#  include <mediaobj.h>
#endif 

#if INCLUDE_DETECT_MSHTMLC
#  include <Mshtmlc.h>
#endif

#if INCLUDE_DETECT_MSXML
#  include <msxml.h>
#endif 

#if INCLUDE_DETECT_OAIDL
#  include <Oaidl.h>
#endif

#if INCLUDE_DETECT_OBJIDL
#  include <ObjIdl.h>
#endif

#if INCLUDE_DETECT_OBJSAFE
#  include <ObjSafe.h>
#endif

#if INCLUDE_DETECT_OCIDL
#  include <OCIdl.h>
#endif 

#if INCLUDE_DETECT_OLEIDL
#  include <OleIdl.h>
#endif 

#if INCLUDE_DETECT_QEDIT
#  include <qedit.h>
#endif 

#if INCLUDE_DETECT_SERVPROV
#  include <ServProv.h>
#endif 

#if INCLUDE_DETECT_SHLOBJ
#  include <ShlObj.h>
#endif 

#if INCLUDE_DETECT_STRMIF
#  include <strmif.h>
#endif 

#if INCLUDE_DETECT_URLMON
#  include <UrlMon.h>
#endif 

#if INCLUDE_DETECT_WMSDKIDL
#  include <wmsdkidl.h>
#endif 

//从自定义列表中检测接口指针支持(能进行QI)的接口
# define COM_DETECT_INTERFACE_FROM_LIST(pUnk) \
    {\
        FTLTRACEEX(FTL::tlTrace, TEXT("%s(%d) : Begin Detect Interface %s( 0x%p ) From List\n"),TEXT(__FILE__),__LINE__,TEXT(#pUnk),pUnk);\
        DWORD dwIntCount = FTL::CFComDetect::CoDetectInterfaceFromList(pUnk,GUID_NULL,FTL::CFComDetect::cdtInterface);\
        FTLTRACEEX(FTL::tlInfo,TEXT("%s's Interfaces Count are at least %d\n\n"),TEXT(#pUnk),dwIntCount);\
    }

//从自定义列表中检测 IMoniker 接口指针能 BindToObject 的接口
# define COM_DETECT_MONIKER_BIND_TO_OBJECT_FROM_LIST(pMoniker)\
    {\
        FTLTRACEEX(FTL::tlTrace,TEXT("%s(%d) : Begin Detect Moniker Can Bind to Object %s( 0x%p ) From List\n"),\
        TEXT(__FILE__),__LINE__,TEXT(#pMoniker),pMoniker);\
        DWORD dwIntCount = FTL::CFComDetect::CoDetectInterfaceFromList(pMoniker,GUID_NULL,FTL::CFComDetect::cdtMonikerBind);\
        FTLTRACEEX(FTL::tlTrace,TEXT("%s Can Bind to at least %d Interfaces\n\n"),TEXT(#pMoniker),dwIntCount);\
    }

//从自定义列表中检测希望检测的RIID是什么接口（如用于 DirectShow 中的 NonDelegatingQueryInterface）
//使用同前面相同的自定义列表
# define COM_DETECT_RIID_FROM_LIST(riid)\
    {\
        USES_CONVERSION;\
        LPOLESTR  lpszRIID = NULL;\
        StringFromIID(riid,&lpszRIID);\
        FTLTRACEEX(FTL::tlTrace,TEXT("%s(%d) : Begin Detect RIID %s(%s) From List\n"),TEXT(__FILE__),__LINE__,TEXT(#riid),OLE2T(lpszRIID));\
        DWORD dwIntCount = FTL::CFComDetect::CoDetectInterfaceFromList(NULL,riid,FTL::CFComDetect::cdtIID);\
        if(0 == dwIntCount)\
        {\
            FTLTRACEEX(tlWarning, TEXT("Can't Detect RIID %s(%s).\n"),TEXT(#riid),OLE2T(lpszRIID));\
        }\
        CoTaskMemFree(lpszRIID);\
    }


//从注册表中检测接口指针支持(能进行QI)的接口
# define COM_DETECT_INTERFACE_FROM_REGISTER(pUnk) \
    {\
        FTLTRACEEX(FTL::tlTrace,TEXT("%s(%d) : Begin Detect Interface %s( 0x%p ) From Register\n"),TEXT(__FILE__),__LINE__,TEXT(#pUnk),pUnk);\
        DWORD dwIntCount = FTL::CFComDetect::CoDetectInterfaceFromRegister(pUnk);\
        FTLTRACEEX(FTL::tlTrace,TEXT("%s's Interfaces Count are at least %d\n\n"),TEXT(#pUnk),dwIntCount);\
    }

#else //FTL_DEBUG
# define COM_DETECT_INTERFACE_FROM_LIST(pUnk)        (void)pUnk;
# define COM_DETECT_RIID_FROM_LIST(riid)             (void)riid;
# define COM_DETECT_INTERFACE_FROM_REGISTER(pUnk)    (void)pUnk;
#endif  //NONE FTL_DEBUG

#ifdef FTL_DEBUG

    #define BEGIN_DETECT_INTERFACE() \
        {\
            HRESULT hr = E_FAIL;\
            DWORD dwInterfaceCount = 0;\
            DWORD dwTotalCheckCount = 0;\
            IMoniker* pMoniker = NULL;\
            if(CFComDetect::cdtMonikerBind == detectType)\
            {\
                COM_VERIFY((pUnknown)->QueryInterface(IID_IMoniker,(void**)(&pMoniker)));\
            }

    #define DETECT_INTERFACE_ENTRY_EX_IID(IntType,riid,classDumpInfo)\
            {\
                dwTotalCheckCount++;\
                if(FTL::CFComDetect::cdtInterface == detectType)\
                {\
                    IntType* p##IntType = NULL;\
                    hr = (pUnknown)->QueryInterface(riid,(void**)(&p##IntType));\
                    if(SUCCEEDED(hr) && p##IntType != NULL)\
                    {\
                        dwInterfaceCount++;\
                        FTLTRACEEX(FTL::tlTrace,TEXT("\t%d: %s\n"),dwInterfaceCount,TEXT(#IntType));\
                        classDumpInfo::DumpInterfaceInfo((IntType*)(p##IntType));\
                        p##IntType->Release();\
                        p##IntType = NULL;\
                    }\
                    else if(E_NOINTERFACE != hr)\
                    {\
                        FTLTRACEEX(tlWarning,TEXT("Warning: Detect %s ,return 0x%p\n"),TEXT(#IntType),hr);\
                    }\
                }\
                else if(FTL::CFComDetect::cdtIID == detectType)\
                {\
                    if(riid == checkRIID)\
                    {\
                        dwInterfaceCount++;\
                        FTLTRACEEX(FTL::tlTrace,TEXT("\tRiid is %s\n"),TEXT(#IntType));\
                    }\
                }\
                else if(FTL::CFComDetect::cdtMonikerBind == detectType)\
                {\
                    IntType* p##IntType = NULL;\
                    hr = (pMoniker)->BindToObject(NULL,NULL,riid,(void**)(&p##IntType));\
                    if(SUCCEEDED(hr) && p##IntType != NULL)\
                    {\
                        dwInterfaceCount++;\
                        FTLTRACEEX(FTL::tlTrace,TEXT("\t%d: %s\n"),dwInterfaceCount,TEXT(#IntType));\
                        p##IntType->Release();\
                        p##IntType = NULL;\
                    }\
                }\
                else\
                {\
                    FTLTRACEEX(tlError,TEXT("\tUnknown Operation \n"));\
                }\
            }

    #define DETECT_INTERFACE_ENTRY_IID(IntType, riid) \
        DETECT_INTERFACE_ENTRY_EX_IID(IntType,riid,CFDummyDump)

    #define DETECT_INTERFACE_ENTRY(IntType) \
        DETECT_INTERFACE_ENTRY_EX_IID(IntType,__uuidof(IntType),CFDummyDump)

    #define DETECT_INTERFACE_ENTRY_EX(IntType,classDumpInfo) \
        DETECT_INTERFACE_ENTRY_EX_IID(IntType,__uuidof(IntType),classDumpInfo)


    #define END_DETECT_INTERFACE()\
            SAFE_RELEASE(pMoniker);\
            if(CFComDetect::cdtInterface == detectType)\
            {\
                FTLTRACEEX(FTL::tlTrace,TEXT("\tTotal Check %d Interfaces\n"),dwTotalCheckCount);\
            }\
            return dwInterfaceCount;\
        }

namespace FTL
{
    class CFComDetect
    {
    public:
        typedef enum ComDetectType
        {
            cdtInterface,
            cdtIID,
            cdtMonikerBind,
        }ComDetectType;

        FTLINLINE static DWORD CoDetectInterfaceFromRegister(IUnknown* pUnk);
        FTLINLINE static DWORD CoDetectInterfaceFromList(IUnknown* pUnknown, REFIID checkRIID, 
            ComDetectType detectType);
    }; //class CFComDetect

#endif //FTL_DEBUG
}//namespace FTL

#endif //FTL_COM_DETECT_H

#ifndef USE_EXPORT
#  include "ftlComDetect.hpp"
#endif