#include "AudioRecorder.h"
#include <iostream>
#include <cstring>
#include <ctime>
#include <sstream>
#include <random>

// Opus settings for Voice 8kHz Mono
#define SAMPLE_RATE 8000
#define CHANNELS 1
#define APPLICATION OPUS_APPLICATION_VOIP
// 60ms frame size = 480 samples at 8kHz
#define FRAME_SIZE 480 

CAudioRecorder::CAudioRecorder() : m_IsRecording(false), m_Encoder(nullptr), m_PacketCount(0), m_GranulePos(0)
{
}

CAudioRecorder::~CAudioRecorder()
{
    Stop();
}

void CAudioRecorder::Cleanup()
{
    if (m_Encoder) {
        opus_encoder_destroy(m_Encoder);
        m_Encoder = nullptr;
    }
    if (m_IsRecording) {
        ogg_stream_clear(&m_OggStream);
    }
    if (m_File.is_open()) {
        m_File.close();
    }
    m_IsRecording = false;
    m_PcmBuffer.clear();
}

std::string CAudioRecorder::Start(const std::string& directory)
{
    std::lock_guard<std::mutex> lock(m_Mutex);
    Cleanup();

    // Use random_device for true randomness/seed
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint16_t> dist(0, 255);

    // Generate UUIDv7 Filename
    uint8_t uuid[16];
    uint8_t rand_bytes[10]; 
    for(int i=0; i<10; ++i) rand_bytes[i] = (uint8_t)dist(gen);

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t unix_ts_ms = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

    uuidv7_generate(uuid, unix_ts_ms, rand_bytes, nullptr);
    
    char uuid_str[37];
    uuidv7_to_string(uuid, uuid_str);
    
    m_Filename = "hearing_" + std::string(uuid_str) + ".opus";
    if (directory.back() == '/')
        m_FullPath = directory + m_Filename;
    else
        m_FullPath = directory + "/" + m_Filename;

    m_File.open(m_FullPath, std::ios::binary | std::ios::out);
    if (!m_File.is_open()) {
        std::cerr << "AudioRecorder: Failed to open file: " << m_FullPath << std::endl;
        return "";
    }

    InitOpus();
    InitOgg(); // No longer calls srand

    m_StartTime = std::time(nullptr);
    m_TotalBytes = 0;
    m_IsRecording = true;
    
    std::cout << "AudioRecorder: Started recording to " << m_Filename << std::endl;
    return m_Filename;
}

void CAudioRecorder::InitOpus()
{
    int err;
    m_Encoder = opus_encoder_create(SAMPLE_RATE, CHANNELS, APPLICATION, &err);
    if (err != OPUS_OK) {
        std::cerr << "AudioRecorder: Failed to create Opus encoder: " << opus_strerror(err) << std::endl;
    }
    opus_encoder_ctl(m_Encoder, OPUS_SET_BITRATE(12000)); // 12kbps
}

void CAudioRecorder::InitOgg()
{
    // Initialize Ogg stream with random serial
    // Use random_device for thread safety
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist; // full int range

    if (ogg_stream_init(&m_OggStream, dist(gen)) != 0) {
        std::cerr << "AudioRecorder: Failed to init Ogg stream" << std::endl;
        return;
    }

    // Create OpusHead packet
    // Magic: "OpusHead" (8 bytes)
    // Version: 1 (1 byte)
    // Channel Count: 1 (1 byte)
    // Pre-skip: 0 (2 bytes)
    // Input Sample Rate: 8000 (4 bytes)
    // Output Gain: 0 (2 bytes)
    // Mapping Family: 0 (1 byte)
    unsigned char header[19] = {
        'O', 'p', 'u', 's', 'H', 'e', 'a', 'd',
        1,
        CHANNELS,
        0, 0,
        0x40, 0x1f, 0x00, 0x00, // 8000 little endian
        0, 0,
        0
    };

    ogg_packet header_packet;
    header_packet.packet = header;
    header_packet.bytes = 19;
    header_packet.b_o_s = 1;
    header_packet.e_o_s = 0;
    header_packet.granulepos = 0;
    header_packet.packetno = m_PacketCount++;

    ogg_stream_packetin(&m_OggStream, &header_packet);
    WriteOggPage(true); // Flush header

    // OpusTags (comments) - Minimal
    // Magic: "OpusTags" (8 bytes)
    // Vendor String Length (4 bytes)
    // Vendor String
    // User Comment List Length (4 bytes)
    const char* vendor = "urfd-recorder";
    uint32_t vendor_len = strlen(vendor);
    
    std::vector<unsigned char> tags;
    tags.reserve(8 + 4 + vendor_len + 4);
    const char* magic = "OpusTags";
    tags.insert(tags.end(), magic, magic + 8);
    
    tags.push_back(vendor_len & 0xFF);
    tags.push_back((vendor_len >> 8) & 0xFF);
    tags.push_back((vendor_len >> 16) & 0xFF);
    tags.push_back((vendor_len >> 24) & 0xFF);
    
    tags.insert(tags.end(), vendor, vendor + vendor_len);
    
    // 0 comments
    tags.push_back(0); tags.push_back(0); tags.push_back(0); tags.push_back(0);

    ogg_packet tags_packet;
    tags_packet.packet = tags.data();
    tags_packet.bytes = tags.size();
    tags_packet.b_o_s = 0;
    tags_packet.e_o_s = 0;
    tags_packet.granulepos = 0;
    tags_packet.packetno = m_PacketCount++;

    ogg_stream_packetin(&m_OggStream, &tags_packet);
    WriteOggPage(true);
}

void CAudioRecorder::WriteOggPage(bool flush)
{
    while(true) {
        int result = flush ? ogg_stream_flush(&m_OggStream, &m_OggPage) : ogg_stream_pageout(&m_OggStream, &m_OggPage);
        if (result == 0) break;
        m_File.write((const char*)m_OggPage.header, m_OggPage.header_len);
        m_File.write((const char*)m_OggPage.body, m_OggPage.body_len);
        m_TotalBytes += m_OggPage.header_len + m_OggPage.body_len;
        m_File.flush();
    }
}

void CAudioRecorder::Write(const int16_t* samples, int count)
{
    if (!m_IsRecording || !m_Encoder) return;

    std::lock_guard<std::mutex> lock(m_Mutex);

    m_PcmBuffer.insert(m_PcmBuffer.end(), samples, samples + count);

    unsigned char out_buf[1024];

    while (m_PcmBuffer.size() >= FRAME_SIZE) {
        int len = opus_encode(m_Encoder, m_PcmBuffer.data(), FRAME_SIZE, out_buf, sizeof(out_buf));
        if (len < 0) {
            std::cerr << "AudioRecorder: Opus encode error: " << len << std::endl;
        } else {
            // Ogg Opus always uses 48kHz for granulepos, regardless of input rate
            // Input: 8000Hz. Frame: 480 samples (60ms).
            // Output: 48000Hz. Frame: 2880 samples (60ms).
            m_GranulePos += FRAME_SIZE * (48000 / SAMPLE_RATE);
            
            ogg_packet packet;
            packet.packet = out_buf;
            packet.bytes = len;
            packet.b_o_s = 0;
            packet.e_o_s = 0;
            packet.granulepos = m_GranulePos;
            packet.packetno = m_PacketCount++;

            ogg_stream_packetin(&m_OggStream, &packet);
            WriteOggPage();
        }

        m_PcmBuffer.erase(m_PcmBuffer.begin(), m_PcmBuffer.begin() + FRAME_SIZE);
    }
}

void CAudioRecorder::Stop()
{
    std::lock_guard<std::mutex> lock(m_Mutex);
    if (!m_IsRecording) return;

    // Actually, just flushing logic
    WriteOggPage(true);

    double duration = std::difftime(std::time(nullptr), m_StartTime);
    std::cout << "AudioRecorder: Stopped recording " << m_Filename 
              << ". Duration: " << duration << "s. Size: " << m_TotalBytes << " bytes." << std::endl;

    Cleanup();
}
