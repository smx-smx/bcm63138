//==============================================================================
//==============================================================================
//
//     Copyright(c) 2008 Media5 Corporation. ("Media5")
//
//  NOTICE:
//   This document contains information that is confidential and proprietary to
//   Media5.
//
//   Media5 reserves all rights to this document as well as to the Intellectual
//   Property of the document and the technology and know-how that it includes
//   and represents.
//
//   This publication cannot be reproduced, neither in whole nor in part, in any
//   form whatsoever, without prior written approval by Media5.
//
//   Media5 reserves the right to revise this publication and make changes at
//   any time and without the obligation to notify any person and/or entity of
//   such revisions and/or changes.
//
//==============================================================================
//==============================================================================
#ifndef MXG_XCAPCLIENTCFG_H
//M5T_INTERNAL_USE_BEGIN
#define MXG_XCAPCLIENTCFG_H
//M5T_INTERNAL_USE_END


//@@TID_COMPILE_CONFIG_HOWTO_UASSP
//<TITLE Configuring the XCAP Client with "PreXCapClientCfg.h">
//<GROUP TID_COMPILE_CONFIG>
//<TOPICORDER 2>
//
// The XCAP Client comes with the file "Config/XcapClientCfg.h", which
// defines many compilation configuration options and values used throughout the
// source code. Generally, these values need updating for the specific
// application being developed with the XCAP Client.
//
// To update these default values, you must create the "PreXcapClientCfg.h"
// file with the updated configuration options for your application.
// "PreXcapClientCfg.h" is always included first by "XcapClientCfg.h" to
// retrieve application-specific configurations, and then the default
// configuration options found in "Config/XcapClientCfg.h" are applied for all
// items that have not been configured by the application.
//
// "PreXcapClientCfg.h" is not packaged with the XCAP Client and must be created
// for the specific application being developed. This file must be placed
// somewhere in the compiler search path to permit the retrieval of the
// application-specific configuration options by the XCAP Client.
//
//==============================================================================
//==============================================================================


// If the compiler complains that it cannot include the file below, it may be
// because:
//
//     1 : You have not created this file to configure your application for
//         using this package. The documentation included with this package
//         explains how the configuration of the various M5T products works.
//         Please refer to this documentation and create "PreXcapClientCfg.h".
//
//     2 : You have created "PreXcapClientCfg.h" but the compiler cannot
//         find it. This file must be located in a directory found within the
//         include path defined for this build. Note that other M5T header files
//         are included by specifying the package name and filename (e.g.:
//         "SipCore/ISipContext.h"), which permits setting the include path to
//         the "Source" directory of the package only, while
//         "PreXcapClientCfg.h" is included without any root directory.
//
//------------------------------------------------------------------------------
#include "PreXcapClientCfg.h"


MX_NAMESPACE_START(MXD_GNS)

// Below this is the documentation of the various configuration macros
// available.
//---------------------------------------------------------------------
#if 0

//<GROUP TID_COMPILE_CONFIG_MACROS>
//
// Summary:
//  Enables the inclusion of "PostXcapClientCfg.h" right at the end of
//  XcapClientCfg.h.
//
// Description:
//  Enables the inclusion of "PostXcapClientCfg.h" right at the end of
//  XcapClientCfg.h. "PostXcapClientCfg.h" is an application-provided file that
//  can contain additional configuration options to possibly override the
//  configuration found in PreXcapClientCfg.h and XcapClientCfg.h.
//
// Location:
//  Define this in PreXcapClientCfg.h or in your makefile.
//
// See Also:
//  PreXcapClientCfg.h
//
//==============================================================================
#define MXD_POST_XCAPCLIENTCFG

//<GROUP TID_COMPILE_CONFIG_MACROS>
//
// Summary:
//  Enables the compilation of the Curl HTTP stack abstraction layer support
//  found in the HTTP folder. Curl HTTP stack abstraction layer support is
//  disabled by default, in which case the Skeleton abstraction layer files are
//  compiled instead.
//
// Description:
//  This permits the compilation of the Curl HTTP stack abstraction layer
//  support found in the HTTP folder. When this is not defined, the HTTP stack
//  abstraction layer specific implementation files found in HTTP are not compiled.
//  HTTP stack abstraction layer is disabled by default. When disabled, it allows
//  the user to implement the IXcapHttpClient interface specifically for another HTTP
//  Stack by implementing the skeleton abstraction layer for his own HTTP stack and
//  use it transparently within the XCAP specific files.
//
// Warning:
//  If disabled, another custom HTTP implementation MUST be provided and
//  compiled for the rest of the XCAP files to work properly. This custom
//  implementation MUST implement the IXcapHttpClient interface, MUST use the
//  IXcapHttpClientMgr interface and its ECOM CLSID MUST be defined as
//  CLSID_CXcapHttpClient. Failure to comply will most likely result in a crash.
//
// Location:
//  Define this in PreXcapClientCfg.h or in your makefile.
//
// See Also:
//  PreXcapClientCfg.h
//
//==============================================================================
#define MXD_XCAP_LIBCURL_ENABLE_SUPPORT


#endif // #if 0 for documentation.


MX_NAMESPACE_END(MXD_GNS)


#if defined(MXD_POST_XCAPCLIENTCFG)
#include "PostXcapClientCfg.h"
#endif


#endif // #ifndef MXG_XCAPCLIENTCFG_H

