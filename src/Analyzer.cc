#include <stdlib.h>
#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"
#include "Analyzer.h"

namespace SMBx 
{
	void Analyzer::Done()
	{
		analyzer::tcp::TCP_ApplicationAnalyzer::Done();
	}

	void Analyzer::EndpointEOF(bool is_orig)
	{
		analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	}

	void Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
		analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

		assert(TCP());
		//if ( TCP()->IsPartial() )
		//	return;

		handler_[orig].handle(len, data);
	}

	void Analyzer::Undelivered(uint64 seq, int len, bool orig)
	{
		analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
		had_gap = true;
	}
}
