#ifndef SMBx_ANALYZER_H
#define SMBx_ANALYZER_H

#include "Reader.h"
#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"
   
namespace SMBx {
	class Handler;
	
	class Analyzer : public analyzer::tcp::TCP_ApplicationAnalyzer {
		public:
			Analyzer(Connection* conn);
			virtual ~Analyzer();
			
			// Overriden from Analyzer.
			virtual void Done();
			virtual void DeliverStream(int len, const u_char* data, bool orig);
			virtual void Undelivered(uint64 seq, int len, bool orig);

			// Overriden from tcp::TCP_ApplicationAnalyzer.
			virtual void EndpointEOF(bool is_orig);			
			
			static analyzer::Analyzer* Instantiate(Connection* conn)
				{ return new Analyzer(conn); }

			static bool Available()
				{ return true; }		
				
		protected:
			Reader* reader_[2];
			Handler* handler_[2];
			bool had_gap;
	};
}

#endif