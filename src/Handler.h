#ifndef SMBx_HANDLER_H
#define SMBx_HANDLER_H

#include <memory>
#include <unordered_map>
#include <utility>
#include "Buffer.h"
#include "Reader.h"
#include "AnalyzerContext.h"
#include "Message.h"

namespace SMBx {
	typedef shared_ptr<SMB2_Body> (*REQUEST_FACTORY)(shared_ptr<SMB2_Header> header);
	typedef shared_ptr<SMB2_Body> (*RESPONSE_FACTORY)(shared_ptr<SMB2_Header> header, shared_ptr<SMB2_Body> request);

	static shared_ptr<SMB2_Body> default_request_factory(shared_ptr<SMB2_Header> header) { return nullptr; }
	static shared_ptr<SMB2_Body> default_response_factory(shared_ptr<SMB2_Header> header, shared_ptr<SMB2_Body> request) { return nullptr; }

	struct CommandPair
	{
		REQUEST_FACTORY request;
		RESPONSE_FACTORY response;

		constexpr CommandPair() : request(&default_request_factory), response(&default_response_factory) { }
		constexpr CommandPair(REQUEST_FACTORY request, RESPONSE_FACTORY response) : request(request), response(response) { }
	};

	class Commands
	{

		private:
		unordered_map<uint16, CommandPair> commands;
		CommandPair default_command;

		public:
		Commands();
		const CommandPair get(uint16 command, bool is_response) const;
	};

	class Handler
	{
		private:
			Commands commands;

			uint16 beginning = 0;
			bool is_last_finished = true;
			bool is_last_parsed = true;

			Buffer buffer;
			Reader reader;
			AnalyzerContext& context;
			shared_ptr<SMB2_Body> current_message;

		public:
			Handler(AnalyzerContext& c) : context(c) {};
			void handle(int len, const u_char* data);

		private:
			bool handle_new();
			void handle_continue();
			shared_ptr<SMB2_Body> get_message(shared_ptr<SMB2_Header> header);
	};
}

#undef SMBX_COMMAND
#endif