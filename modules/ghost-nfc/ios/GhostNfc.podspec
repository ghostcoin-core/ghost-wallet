Pod::Spec.new do |s|
  s.name           = 'GhostNfc'
  s.version        = '0.1.0'
  s.summary        = 'Phantom Keys on NTAG 424 DNA cards: Core NFC, the card keys in the Keychain, and the chip crypto.'
  s.description    = s.summary
  s.author         = 'Ghost Wallet'
  s.homepage       = 'https://github.com/ghostcoin-core/ghost'
  s.license        = { :type => 'MIT OR Apache-2.0' }
  s.platforms      = { :ios => '15.1' }
  s.source         = { :git => '' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'
  s.frameworks = 'CoreNFC', 'Security', 'CryptoKit'

  # GhostCardBridge.h declares the two C functions of core/src/card.rs. The
  # native core's XCFramework, linked by the GhostCore pod, defines them; the
  # Phantom Key crosses between the core and this module there and nowhere
  # else. DEFINES_MODULE makes the header visible to Swift.
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
  }

  s.source_files = '**/*.{swift,h}'
end
