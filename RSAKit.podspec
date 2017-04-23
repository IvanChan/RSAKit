#
# Be sure to run `pod lib lint RSAKit.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'RSAKit'
  s.version      = "0.9.0"
  s.summary      = "RSA api for Objective-C."

# This description is used to generate tags and improve search results.
#   * Think: What does it do? Why did you write it? What is the focus?
#   * Try to keep it short, snappy and to the point.
#   * Write the description between the DESC delimiters below.
#   * Finally, don't worry about the indent, CocoaPods strips it!

  s.description      = <<-DESC
RSA api for Objective-C, use this api for RSA encrypt/decrypt or sign/verify your data.
                       DESC

  s.homepage         = 'https://github.com/IvanChan/RSAKit'
  # s.screenshots     = 'www.example.com/screenshots_1', 'www.example.com/screenshots_2'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { '_ivanC' => '_ivanC' }
  s.source           = { :git => 'https://github.com/IvanChan/RSAKit.git', :tag => s.version.to_s }
  # s.social_media_url = 'https://twitter.com/<TWITTER_USERNAME>'

  s.ios.deployment_target = '7.0'

  s.source_files = 'RSAKit/Classes/**/*'
  s.public_header_files = 'RSAKit/Classes/**/*.h'

  # s.resource_bundles = {
  #   'RSAKit' => ['RSAKit/Assets/*.png']
  # }

  s.frameworks = 'Security'
  # s.dependency 'AFNetworking', '~> 2.3'
end
