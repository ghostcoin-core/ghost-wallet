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

  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
  }

  s.source_files = '**/*.swift'
end
