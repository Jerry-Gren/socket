#ifndef GLOG_WRAPPER_H_
#define GLOG_WRAPPER_H_

#include <iostream>
#include <string>
#include <filesystem>
#include <glog/logging.h> // For glog

class GlogWrapper
{
public:
	GlogWrapper(char *program, bool also_log_to_stderr = true)
	{
		const std::string log_dir = "./logs";
		if (!std::filesystem::exists(log_dir)) {
			if (also_log_to_stderr) {
				std::cerr << "Log directory '" << log_dir
				          << "' not found. Creating it..." << std::endl;
			}
			std::filesystem::create_directory(log_dir);
		}

		FLAGS_log_dir = log_dir; // Set log saving prefix
		FLAGS_alsologtostderr = also_log_to_stderr;
		FLAGS_colorlogtostderr = true;
		FLAGS_stop_logging_if_full_disk = true;
		// FLAGS_stderrthreshold=google::WARNING; // Logging level

		google::InitGoogleLogging(program);
		google::InstallFailureSignalHandler();
	}

	~GlogWrapper()
	{
		google::ShutdownGoogleLogging();
	}
};

#endif // GLOG_WRAPPER_H_
