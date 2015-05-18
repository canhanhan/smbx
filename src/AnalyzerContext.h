#ifndef SMBx_ANALYZERCONTEXT_H
#define SMBx_ANALYZERCONTEXT_H

#include "Conn.h"
#include "Event.h"
#include "State.h"

namespace SMBx {
	class AnalyzerContext 
	{
		public:
		Connection* conn;
		analyzer::ID id;
		analyzer::Tag tag;
		State state;
		
		AnalyzerContext(Connection* c, analyzer::ID id, analyzer::Tag tag) : conn(c), id(id), tag(tag) {}
		
		void QueueEvent(const EventHandlerPtr& ptr, val_list* vl) 
		{
			mgr.QueueEvent(ptr, vl, SOURCE_LOCAL, id, timer_mgr, conn);
		}
	};
}

#endif