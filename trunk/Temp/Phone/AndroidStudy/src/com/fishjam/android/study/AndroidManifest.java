package com.fishjam.android.study;
import android.test.AndroidTestCase;
import junit.framework.Assert;

/**************************************************************************************************************************************
 * AndroidManifest.xml -- 系统清单文件，控制应用的名称、图标、访问权限等属性， 
 *   也包含这个Android应用程序具有哪些Activity、Service、Provider、Receiver 等，所有组件必须在其中声明后才能使用。
 * <application>
 *   <activity android:name=".MainActivity" android:label="@string/app_name> -- 声明Activity
 *   <provider android:name="EmployeeProvider" android:authorities="com.fishjam.android.study.Employees" /> -- 声明 ContentProvider
 *   <receiver android:name="MyReceiver"> -- 声明 BroadcastReceiver
 *   <service android:name="MyService"> -- 声明Service
 *     <intent-filter> -- 指定访问能力。action指定程序入口?; category 指定 LAUNCHER(加载程序时运行),  等
 *       <action>
 *       <category>
 *       <data>
 * <uses-sdk> -- 指定SDk的版本信息
 *   minSdkVersion -- 可以支持的最低版本等级
 *   targetSdkVersion -- ? 指定该版本即允许平台禁用不需要的兼容性代码或者能使新的功能运行在旧版本的程序里 
 * 
 * 
 *  
**************************************************************************************************************************************/

public class AndroidManifest  extends AndroidTestCase{
	public void testSave() throws Throwable
	{
		int i=4+8;
		Assert.assertEquals(12,i);
	}
}

