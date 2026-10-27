Pod::Spec.new do |s|
  s.name           = 'GhostBench'
  s.version        = '0.1.0'
  s.summary        = 'Feasibility harness: runs named native benchmarks and records time, memory and heat.'
  s.description    = s.summary
  s.author         = 'Ghost Wallet'
  s.homepage       = 'https://github.com/ghostcoin-core/ghost'
  s.license        = { :type => 'MIT OR Apache-2.0' }
  s.platforms      = { :ios => '15.1' }
  s.source         = { :git => '' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'

  # The Swift bindings of the native core (ghost_wallet_core.swift and
  # ghost_wallet_coreFFI.h) are written into Generated/ by the install scripts
  # and compiled as part of this pod, so the benchmarks call them without an
  # import. GhostCore already links the core's XCFramework; it is not vendored
  # here again. DEFINES_MODULE makes the FFI header visible to Swift.
  bindings = File.exist?(File.join(__dir__, 'Generated', 'ghost_wallet_core.swift'))

  xcconfig = {
    'DEFINES_MODULE' => 'YES',
  }
  xcconfig['SWIFT_ACTIVE_COMPILATION_CONDITIONS'] = '$(inherited) GHOST_CORE_BINDINGS' if bindings
  s.pod_target_xcconfig = xcconfig

  s.source_files = '**/*.{swift,h}'
end
