/*
	Original C Code
		-- Steve Reid <steve@edmweb.com>
	Small changes to fit into bglibs
		-- Bruce Guenter <bruce@untroubled.org>
	Translation to simpler C++ Code
		-- Volker Grabsch <vog@notjusthosting.com>
	Safety fixes
		-- Eugene Hopkinson <slowriot at voxelstorm dot com>
	Stupid stylistic gamedev changes
		-- Evan Todd <evan@etodd.io>
*/

#pragma once

#include <cstdint>

namespace sha1
{

	void hash(const char*, char*);

	struct Digest
	{
		uint64_t transforms;
		std::size_t buffer_size;
		uint32_t digest[5];
		char buffer[64];

		Digest();
		void update(const char*);
		void final(char*);
		void reset();
	};


}
