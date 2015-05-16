
#ifndef BRO_PLUGIN_CUSTOM_SMB
#define BRO_PLUGIN_CUSTOM_SMB

namespace plugin {
namespace Custom_SMB {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	virtual plugin::Configuration Configure();
};

extern Plugin plugin;

}
}

#endif
