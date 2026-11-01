Pod::Spec.new do |s|
  s.name = 'T3Attestation'
  s.version = '1.0.0'
  s.summary = 'Device-owned verification transport for T3.'
  s.author = 'T3 fork contributors'
  s.homepage = 'https://github.com/elchiapp/t3code'
  s.license = { :type => 'MIT' }
  s.platforms = { :ios => '18.0' }
  s.source = { :path => '.' }
  s.static_framework = true
  s.dependency 'ExpoModulesCore'
  s.dependency 'React-Core'
  s.dependency 'React-CoreModules'
  s.dependency 'React-RCTNetwork'
  s.dependency 'SocketRocket'
  s.source_files = '**/*.{h,m,mm,swift}'
  s.public_header_files = '*.h'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
end
