#ifndef SMBx_ANALYZER_H
#define SMBx_ANALYZER_H

#include <memory>
#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"
#include "file_analysis/Manager.h"
#include "AnalyzerContext.h"
#include "State.h"
#include "Handler.h"

namespace SMBx {
	class Analyzer : public analyzer::tcp::TCP_ApplicationAnalyzer {
		public:
			Analyzer(Connection* conn): analyzer::tcp::TCP_ApplicationAnalyzer("SMBx", conn), context_(conn, GetID(), GetAnalyzerTag()) {}

			// Overriden from Analyzer.
			void Done() final override;
			void DeliverStream(int len, const u_char* data, bool orig) final override;
			void Undelivered(uint64 seq, int len, bool orig) final override;

			// Overriden from tcp::TCP_ApplicationAnalyzer.
			void EndpointEOF(bool is_orig) override;
			static analyzer::Analyzer* Instantiate(Connection* conn)
				{ return new Analyzer(conn); }

			static bool Available()
				{ return true; }

		protected:
			bool had_gap = false;
			AnalyzerContext context_;
			array<Handler, 2> handler_ { { Handler(context_), Handler(context_) } };
	};
}

#endif
