#ifndef FDRIVER_KERNEL_H
#define FDRIVER_KERNEL_H

//NtCurrentPeb()->KernelCallbackTable

/******************************************************************************************************************
* CSRSS.exe -- Console, TS, HardError ?
* WinLogon.exe
******************************************************************************************************************/

/******************************************************************************************************************
* Ntdll.dll --
*   KiFastSystemCall -- 
******************************************************************************************************************/

/******************************************************************************************************************
* Win32k.sys -- Windows子系统在核心侧的实现，主要负责 User(窗体管理)、GDI、DX(dxg.sys)的入口 -- Dxthunksto dxg.sys
*   里面有三个表(table)?
*     1.W32pServiceTable(function & Return value)
*     2.W32pArgument
*     3.TableProvidedto NT kernel via KeAddSystemServiceTableon initialization
******************************************************************************************************************/

#endif //FDRIVER_KERNEL_H