#include "AudioRecorder.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <thread>
#include <chrono>

int main() {
    CAudioRecorder recorder;
    std::string filename = recorder.Start(".");
    std::cout << "Recording started: " << filename << std::endl;

    if (filename.empty()) {
        std::cerr << "Failed to start recording" << std::endl;
        return 1;
    }

    // Generate 5 seconds of 440Hz sine wave
    std::vector<int16_t> samples;
    int sampleRate = 8000;
    int duration = 5;
    double frequency = 440.0;
    int totalSamples = sampleRate * duration;

    for (int i = 0; i < totalSamples; ++i) {
        double time = (double)i / sampleRate;
        int16_t sample = (int16_t)(32000.0 * std::sin(2.0 * M_PI * frequency * time));
        samples.push_back(sample);
    }

    // Write in chunks
    int chunkSize = 160;
    for (int i = 0; i < totalSamples; i += chunkSize) {
        recorder.Write(samples.data() + i, chunkSize);
        std::this_thread::sleep_for(std::chrono::milliseconds(20)); // Simulate real-time
    }

    recorder.Stop();
    std::cout << "Recording stopped." << std::endl;

    return 0;
}
