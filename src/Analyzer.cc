#include <stdlib.h>
#include "Analyzer.h"
#include "Handler.h"
#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"

namespace SMBx 
{
	Analyzer::Analyzer(Connection* c) : analyzer::tcp::TCP_ApplicationAnalyzer("SMBx", c)
	{
		had_gap = false;
		reader_[0] = new Reader();
		reader_[1] = new Reader();
		handler_[0] = new Handler(this, reader_[0]);
		handler_[1] = new Handler(this, reader_[1]);
	}

	Analyzer::~Analyzer()
	{
		delete[] handler_;
		delete[] reader_;
	}
	
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
		if ( TCP()->IsPartial() )
			return;

		handler_[orig]->handle(len, data);
	}

	void Analyzer::Undelivered(uint64 seq, int len, bool orig)
	{
		analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
		had_gap = true;
	}
}