#include "xdeflatedecoder.h"
#include "xzstddecoder.h"
#include "xbrotlidecoder.h"

bool XDeflateDecoder::decompress(XBinary::DATAPROCESS_STATE *, XBinary::PDSTRUCT *)         { return false; }
bool XDeflateDecoder::decompress64(XBinary::DATAPROCESS_STATE *, XBinary::PDSTRUCT *)       { return false; }
bool XDeflateDecoder::decompress_zlib(XBinary::DATAPROCESS_STATE *, XBinary::PDSTRUCT *)    { return false; }
bool XDeflateDecoder::compress(XBinary::DATAPROCESS_STATE *, XBinary::PDSTRUCT *, int)      { return false; }
bool XDeflateDecoder::compress_zlib(XBinary::DATAPROCESS_STATE *, XBinary::PDSTRUCT *, int) { return false; }

bool XZstdDecoder::decompress(XBinary::DATAPROCESS_STATE *, XBinary::PDSTRUCT *)            { return false; }
bool XBrotliDecoder::decompress(XBinary::DATAPROCESS_STATE *, XBinary::PDSTRUCT *)          { return false; }
