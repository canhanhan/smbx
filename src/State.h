#ifndef SMBx_STATE_H
#define SMBx_STATE_H

namespace SMBx {
	class SMB2_Body;
	
	typedef map<uint64, shared_ptr<SMB2_Body>> state_map;
	class SMB2_File 
	{	
		public:
		uint64 id;
		string file_id;				
		string name;
		string tree_name;
		string path;
		
		SMB2_File(uint64 id, string tree_name, string name);				
		~SMB2_File();
	};	
	typedef map<uint32, shared_ptr<SMB2_File>> file_map;
	typedef map<uint32, shared_ptr<string>> treeconnection_map;
	
	class SMB2_Session
	{			
		public:
		uint64 id;
		
		SMB2_Session(uint64 id) : id(id) {};		
		file_map files;
		treeconnection_map tree_connections;
	};
	typedef map<uint64, shared_ptr<SMB2_Session>> session_map;
	
	class State
	{
		private:
		session_map sessions;
		state_map states;
		
		public:
		void NewSession(uint64 id);
		void NewTreeConnection(uint64 session_id, uint32 tree_id, string name);
		void NewFile(uint64 session_id, uint32 tree_id, uint64 file_id, string name);
		void CloseFile(uint64 session_id, uint32 tree_id, uint64 file_id);
		void CloseTreeConnection(uint64 session_id, uint32 tree_id);
		void CloseSession(uint64 id);
		shared_ptr<SMB2_Session> GetSession(uint64 session_id);
		shared_ptr<string> GetTreeConnection(uint64 session_id, uint32 tree_id);
		shared_ptr<SMB2_File> GetFile(uint64 session_id, uint32 tree_id, uint64 file_id);	
		
		void PushMessage(uint64 message_id, shared_ptr<SMB2_Body> message);
		shared_ptr<SMB2_Body> PopMessage(uint64 message_id);		
	};
}

#endif