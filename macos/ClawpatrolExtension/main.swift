// System extension entry point. Kernel loads this binary as the
// principal class declared in Info.plist (TransparentProxyProvider).
import Foundation
import NetworkExtension

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
dispatchMain()
