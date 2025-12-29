#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include <mutex>
#include <opus/opus.h>
#include <ogg/ogg.h>
#include "uuidv7.h"

class CAudioRecorder
{
public:
    CAudioRecorder();
    ~CAudioRecorder();

    // Starts recording to a new file.
    // Generates a UUIDv7 based filename if path is a directory,
    // or uses the provided path + generated filename.
    // Returns the filename (without path) for notification.
    std::string Start(const std::string& directory);

    // Writes signed 16-bit PCM samples (8kHz mono)
    void Write(const int16_t* samples, int count);

    // Stops recording and closes file.
    void Stop();

    bool IsRecording() const { return m_IsRecording; }

private:
    void InitOpus();
    void InitOgg();
    void WriteOggPage(bool flush = false);
    void Cleanup();

    bool m_IsRecording;
    std::ofstream m_File;
    std::string m_Filename;
    std::string m_FullPath;
    std::mutex m_Mutex;

    // Opus state
    OpusEncoder* m_Encoder;
    
    // Ogg state
    ogg_stream_state m_OggStream;
    ogg_page         m_OggPage;
    ogg_packet       m_OggPacket;
    int              m_PacketCount;
    int              m_GranulePos;

    // Buffering pcm for frame size
    std::vector<int16_t> m_PcmBuffer;
};
