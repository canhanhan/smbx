#include "plugin/Plugin.h"
#include "Analyzer.h"

namespace plugin { namespace Custom_SMB { 

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure() {
		AddComponent(new ::analyzer::Component("SMBx", ::SMBx::Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Custom::SMB";
		config.description = "SMB Analyzer";
		config.version.major = 0;
		config.version.minor = 1;
		return config;
	}
} plugin;
}}
