
因为perf原生的用户态工具(kerneldir/tools/perf)交叉编译出错较多，用户态源码分析改用android 7.0简化版simpleperf来分析。simpleperf支持完整perf命令中的一些常见子命令。

# 1、命令框架

源码入口在system/extras/simpleperf/main.cpp:

```
int main(int argc, char** argv) {
  InitLogging(argv, android::base::StderrLogger);
  std::vector<std::string> args;
  android::base::LogSeverity log_severity = android::base::WARNING;

  /* (1) 解析命令参数“simpleperf xxx”：从argv[i]解析到args */
  for (int i = 1; i < argc; ++i) {
  
    /* (1.1) help子命令 */
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      args.insert(args.begin(), "help");
    
    /* (1.2) 指定log等级 */
    } else if (strcmp(argv[i], "--log") == 0) {
      if (i + 1 < argc) {
        ++i;
        if (!GetLogSeverity(argv[i], &log_severity)) {
          LOG(ERROR) << "Unknown log severity: " << argv[i];
          return 1;
        }
      } else {
        LOG(ERROR) << "Missing argument for --log option.\n";
        return 1;
      }
    
    /* (1.3) 其他的不解析直接压入args */
    } else {
      args.push_back(argv[i]);
    }
  }
  
  /* (1.4) 设定log等级 */
  android::base::ScopedLogSeverity severity(log_severity);

  /* (1.5) 如果参数为空，设置参数为"help" */
  if (args.empty()) {
    args.push_back("help");
  }
  
  /* (2) 根据args[0]指定的命令名，找到注册的对应命令command */
  std::unique_ptr<Command> command = CreateCommandInstance(args[0]);
  if (command == nullptr) {
    LOG(ERROR) << "malformed command line: unknown command " << args[0];
    return 1;
  }
  std::string command_name = args[0];
  args.erase(args.begin());

  LOG(DEBUG) << "command '" << command_name << "' starts running";
  /* (3) 调用command对象的Run()方法 */
  bool result = command->Run(args);
  LOG(DEBUG) << "command '" << command_name << "' "
             << (result ? "finished successfully" : "failed");
  return result ? 0 : 1;
}

|→

std::unique_ptr<Command> CreateCommandInstance(const std::string& cmd_name) {

  /* (2.1) 根据name从command map中找到对应command对象 */
  auto it = CommandMap().find(cmd_name);
  return (it == CommandMap().end()) ? nullptr : (it->second)();
}
```

command map是通过RegisterCommand()来进行注册的，在CommandRegister对象的构造函数中统一注册：

```

/* (1) 类 */
class CommandRegister {
 public:
 
  /* (1.1) 构造函数 */
  CommandRegister() {
    RegisterDumpRecordCommand();
    RegisterHelpCommand();
    RegisterReportCommand();
#if defined(__linux__)
    RegisterListCommand();
    RegisterRecordCommand();
    RegisterStatCommand();
#endif
  }
};

/* (2) 定义一个全局对象来调用构造函数 */
CommandRegister command_register;

|→

void RegisterListCommand() {

  /* (1.1.1) 向command map中注册("list", (new ListCommand))序列对 */
  RegisterCommand("list", [] { return std::unique_ptr<Command>(new ListCommand); });
}

void RegisterRecordCommand() {
  RegisterCommand("record", [] { return std::unique_ptr<Command>(new RecordCommand()); });
}

void RegisterStatCommand() {
  RegisterCommand("stat", [] { return std::unique_ptr<Command>(new StatCommand); });
}

||→

void RegisterCommand(const std::string& cmd_name,
                     std::function<std::unique_ptr<Command>(void)> callback) {
                     
  /* (1.1.1.1) 将序列对压入CommandMap() */ 
  CommandMap().insert(std::make_pair(cmd_name, callback));
}

```


# 2、list子命令

我们使用“simple list”来查看当前系统支持event的种类：

```
# simpleperf list | more
List of hw-cache events:
  L1-dcache-loads
  L1-dcache-load-misses
  L1-dcache-stores
  L1-dcache-store-misses
  branch-loads
  branch-load-misses
  branch-stores
  branch-store-misses

List of hardware events:
  cpu-cycles
  instructions
  cache-references
  cache-misses
  branch-misses

List of software events:
  cpu-clock
  task-clock
  page-faults
  context-switches
  cpu-migrations
  minor-faults
  major-faults
  alignment-faults
  emulation-faults

List of tracepoint events:
  almk:almk_shrink
  almk:almk_vmpressure
  asoc:snd_soc_bias_level_done
  asoc:snd_soc_bias_level_start
  asoc:snd_soc_dapm_connected
  asoc:snd_soc_dapm_done
  asoc:snd_soc_dapm_path
  asoc:snd_soc_dapm_start
  asoc:snd_soc_dapm_walk_done
  asoc:snd_soc_dapm_widget_event_done
  asoc:snd_soc_dapm_widget_event_start
```

list子命令的实现主体在ListCommand的Run方法中，system/extras/simpleperf/cmd_list.cpp:

```
bool ListCommand::Run(const std::vector<std::string>& args) {

  /* (1) 权限判断 */
  if (!CheckPerfEventLimit()) {
    return false;
  }

  static std::map<std::string, std::pair<int, std::string>> type_map = {
      {"hw", {PERF_TYPE_HARDWARE, "hardware events"}},
      {"sw", {PERF_TYPE_SOFTWARE, "software events"}},
      {"cache", {PERF_TYPE_HW_CACHE, "hw-cache events"}},
      {"tracepoint", {PERF_TYPE_TRACEPOINT, "tracepoint events"}},
  };

  /* (2) “simpleperf list xxx”子参数的判断 */
  std::vector<std::string> names;
  /* (2.1) 如果子参数为空，默认把type_map表中所有type加入到names对象 */
  if (args.empty()) {
    for (auto& item : type_map) {
      names.push_back(item.first);
    }
  /* (2.2) 如果子参数不为空，判断是否符合type_map表中type，并加入到names对象 */
  } else {
    for (auto& arg : args) {
      if (type_map.find(arg) != type_map.end()) {
        names.push_back(arg);
      } else {
        LOG(ERROR) << "unknown event type category: " << arg << ", try using \"help list\"";
        return false;
      }
    }
  }

  /* (3) 获取到总type底下，具体子config的全集 */
  auto& event_types = GetAllEventTypes();

  /* (4) 根据命令参数指定的type，找出所有的子config 
        逐个尝试当前系统是否支持
   */
  for (auto& name : names) {
    auto it = type_map.find(name);
    PrintEventTypesOfType(it->second.first, it->second.second, event_types);
  }
  return true;
}
```

“type + config”的全集在GetAllEventTypes()函数中获取：

```
const std::vector<EventType>& GetAllEventTypes() {
  static std::vector<EventType> event_type_array;
  if (event_type_array.empty()) {
  
    /* (3.1) software和hardware event在static_event_type_array[]数组中定义 */
    event_type_array.insert(event_type_array.end(), static_event_type_array.begin(),
                            static_event_type_array.end());
    
    /* (3.2) tracepoint event通过轮询"/sys/kernel/debug/tracing/events"下的文件夹来添加 */
    const std::vector<EventType> tracepoint_array = GetTracepointEventTypes();
    event_type_array.insert(event_type_array.end(), tracepoint_array.begin(),
                            tracepoint_array.end());
  }
  return event_type_array;
}

|→

static const std::vector<EventType> static_event_type_array = {
#include "event_type_table.h"

↓

 /* (3.1.1) software和hardware event的详细定义 */
// This file is auto-generated by generate-event_table.py.

{"cpu-cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES},
{"instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS},
{"cache-references", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES},
{"cache-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES},
{"branch-instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
{"branch-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES},
{"bus-cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BUS_CYCLES},
{"stalled-cycles-frontend", PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_FRONTEND},
{"stalled-cycles-backend", PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_BACKEND},

{"cpu-clock", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK},
{"task-clock", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_TASK_CLOCK},
{"page-faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS},
{"context-switches", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES},
{"cpu-migrations", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_MIGRATIONS},
{"minor-faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MIN},
{"major-faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MAJ},
{"alignment-faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_ALIGNMENT_FAULTS},
{"emulation-faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_EMULATION_FAULTS},

{"L1-dcache-loads", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_L1D) | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))},
{"L1-dcache-load-misses", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_L1D) | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))},
{"L1-dcache-stores", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_L1D) | (PERF_COUNT_HW_CACHE_OP_WRITE << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))},
{"L1-dcache-store-misses", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_L1D) | (PERF_COUNT_HW_CACHE_OP_WRITE << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))},
{"L1-dcache-prefetches", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_L1D) | (PERF_COUNT_HW_CACHE_OP_PREFETCH << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))},
{"L1-dcache-prefetch-misses", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_L1D) | (PERF_COUNT_HW_CACHE_OP_PREFETCH << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))},
{"L1-icache-loads", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_L1I) | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))},
{"L1-icache-load-misses", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_L1I) | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))},
{"L1-icache-stores", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_L1I) | (PERF_COUNT_HW_CACHE_OP_WRITE << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))},
{"L1-icache-store-misses", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_L1I) | (PERF_COUNT_HW_CACHE_OP_WRITE << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))},
{"L1-icache-prefetches", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_L1I) | (PERF_COUNT_HW_CACHE_OP_PREFETCH << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))},
{"L1-icache-prefetch-misses", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_L1I) | (PERF_COUNT_HW_CACHE_OP_PREFETCH << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))},
{"LLC-loads", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_LL) | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))},
{"LLC-load-misses", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_LL) | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))},
{"LLC-stores", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_LL) | (PERF_COUNT_HW_CACHE_OP_WRITE << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))},
{"LLC-store-misses", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_LL) | (PERF_COUNT_HW_CACHE_OP_WRITE << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))},
{"LLC-prefetches", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_LL) | (PERF_COUNT_HW_CACHE_OP_PREFETCH << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))},
{"LLC-prefetch-misses", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_LL) | (PERF_COUNT_HW_CACHE_OP_PREFETCH << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))},
{"dTLB-loads", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_DTLB) | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))},
{"dTLB-load-misses", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_DTLB) | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))},
{"dTLB-stores", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_DTLB) | (PERF_COUNT_HW_CACHE_OP_WRITE << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))},
{"dTLB-store-misses", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_DTLB) | (PERF_COUNT_HW_CACHE_OP_WRITE << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))},
{"dTLB-prefetches", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_DTLB) | (PERF_COUNT_HW_CACHE_OP_PREFETCH << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))},
{"dTLB-prefetch-misses", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_DTLB) | (PERF_COUNT_HW_CACHE_OP_PREFETCH << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))},
{"iTLB-loads", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_ITLB) | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))},
{"iTLB-load-misses", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_ITLB) | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))},
{"iTLB-stores", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_ITLB) | (PERF_COUNT_HW_CACHE_OP_WRITE << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))},
{"iTLB-store-misses", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_ITLB) | (PERF_COUNT_HW_CACHE_OP_WRITE << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))},
{"iTLB-prefetches", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_ITLB) | (PERF_COUNT_HW_CACHE_OP_PREFETCH << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))},
{"iTLB-prefetch-misses", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_ITLB) | (PERF_COUNT_HW_CACHE_OP_PREFETCH << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))},
{"branch-loads", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_BPU) | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))},
{"branch-load-misses", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_BPU) | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))},
{"branch-stores", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_BPU) | (PERF_COUNT_HW_CACHE_OP_WRITE << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))},
{"branch-store-misses", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_BPU) | (PERF_COUNT_HW_CACHE_OP_WRITE << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))},
{"branch-prefetches", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_BPU) | (PERF_COUNT_HW_CACHE_OP_PREFETCH << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))},
{"branch-prefetch-misses", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_BPU) | (PERF_COUNT_HW_CACHE_OP_PREFETCH << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))},
{"node-loads", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_NODE) | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))},
{"node-load-misses", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_NODE) | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))},
{"node-stores", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_NODE) | (PERF_COUNT_HW_CACHE_OP_WRITE << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))},
{"node-store-misses", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_NODE) | (PERF_COUNT_HW_CACHE_OP_WRITE << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))},
{"node-prefetches", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_NODE) | (PERF_COUNT_HW_CACHE_OP_PREFETCH << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))},
{"node-prefetch-misses", PERF_TYPE_HW_CACHE, ((PERF_COUNT_HW_CACHE_NODE) | (PERF_COUNT_HW_CACHE_OP_PREFETCH << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))},

};

|→

static const std::vector<EventType> GetTracepointEventTypes() {
  std::vector<EventType> result;
  const std::string tracepoint_dirname = "/sys/kernel/debug/tracing/events";
  std::vector<std::string> system_dirs;
  GetEntriesInDir(tracepoint_dirname, nullptr, &system_dirs);
  
  /* (3.2.1) 遍历"/sys/kernel/debug/tracing/events"下的子文件夹 */
  for (auto& system_name : system_dirs) {
    std::string system_path = tracepoint_dirname + "/" + system_name;
    std::vector<std::string> event_dirs;
    GetEntriesInDir(system_path, nullptr, &event_dirs);
    for (auto& event_name : event_dirs) {
      std::string id_path = system_path + "/" + event_name + "/id";
      std::string id_content;
      if (!android::base::ReadFileToString(id_path, &id_content)) {
        continue;
      }
      char* endptr;
      uint64_t id = strtoull(id_content.c_str(), &endptr, 10);
      if (endptr == id_content.c_str()) {
        LOG(DEBUG) << "unexpected id '" << id_content << "' in " << id_path;
        continue;
      }
      
      /* (3.2.2) 得到tracepoint event具体的值 */
      result.push_back(EventType(system_name + ":" + event_name, PERF_TYPE_TRACEPOINT, id));
    }
  }
  std::sort(result.begin(), result.end(),
            [](const EventType& type1, const EventType& type2) { return type1.name < type2.name; });
  return result;
}
```

逐个尝试“type + config”组合在当前系统中是否支持，PrintEventTypesOfType()：

```
static void PrintEventTypesOfType(uint32_t type, const std::string& type_name,
                                  const std::vector<EventType>& event_types) {
  printf("List of %s:\n", type_name.c_str());
  
  /* (4.1) 从全集中遍历符合当前type的所有config */
  for (auto& event_type : event_types) {
    if (event_type.type == type) {
    
      /* (4.2) 创建默认的属性attr */
      perf_event_attr attr = CreateDefaultPerfEventAttr(event_type);
      // Exclude kernel to list supported events even when
      // /proc/sys/kernel/perf_event_paranoid is 2.
      attr.exclude_kernel = 1;
      
      /* (4.3) 使用attr尝试使用perf_event_open()系统调用，如果调用ok说明本系统支持 */
      if (IsEventAttrSupportedByKernel(attr)) {
        printf("  %s\n", event_type.name.c_str());
      }
    }
  }
  printf("\n");
}

|→

perf_event_attr CreateDefaultPerfEventAttr(const EventType& event_type) {
  perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(perf_event_attr);
  attr.type = event_type.type;
  attr.config = event_type.config;
  attr.mmap = 1;
  attr.comm = 1;
  attr.disabled = 0;
  // Changing read_format affects the layout of the data read from perf_event_file, namely
  // PerfCounter in event_fd.h.
  attr.read_format =
      PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING | PERF_FORMAT_ID;
  attr.sample_type |=
      PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CPU;

  if (attr.type == PERF_TYPE_TRACEPOINT) {
    attr.sample_freq = 0;
    attr.sample_period = 1;
    // Tracepoint information are stored in raw data in sample records.
    attr.sample_type |= PERF_SAMPLE_RAW;
  }
  return attr;
}

|→

bool IsEventAttrSupportedByKernel(perf_event_attr attr) {

  /* (4.3.1) pid = getpid(), cpu = -1 */
  auto event_fd = EventFd::OpenEventFile(attr, getpid(), -1, false);
  return event_fd != nullptr;
}

||→

std::unique_ptr<EventFd> EventFd::OpenEventFile(const perf_event_attr& attr, pid_t tid, int cpu,
                                                bool report_error) {
  perf_event_attr perf_attr = attr;
  std::string event_name = "unknown event";
  const EventType* event_type = FindEventTypeByConfig(perf_attr.type, perf_attr.config);
  if (event_type != nullptr) {
    event_name = event_type->name;
  }
  
  /* (4.3.1.1) 使用perf_event_open()系统调用得到fd */
  int perf_event_fd = perf_event_open(&perf_attr, tid, cpu, -1, 0);
  if (perf_event_fd == -1) {
    if (report_error) {
      PLOG(ERROR) << "open perf_event_file (event " << event_name << ", tid " << tid << ", cpu "
                  << cpu << ") failed";
    } else {
      PLOG(DEBUG) << "open perf_event_file (event " << event_name << ", tid " << tid << ", cpu "
                  << cpu << ") failed";
    }
    return nullptr;
  }
  
  /* (4.3.1.2) 使用fcntl系统调用配置fd的属性 */
  if (fcntl(perf_event_fd, F_SETFD, FD_CLOEXEC) == -1) {
    if (report_error) {
      PLOG(ERROR) << "fcntl(FD_CLOEXEC) for perf_event_file (event " << event_name << ", tid "
                  << tid << ", cpu " << cpu << ") failed";
    } else {
      PLOG(DEBUG) << "fcntl(FD_CLOEXEC) for perf_event_file (event " << event_name << ", tid "
                  << tid << ", cpu " << cpu << ") failed";
    }
    return nullptr;
  }
  return std::unique_ptr<EventFd>(new EventFd(perf_event_fd, event_name, tid, cpu));
}
```

# 3、stat子命令

我们经常使用“simpleperf stat xxx”命令在查看，在执行“xxx”命令的过程中，各个event的count的统计情况：

```
# simpleperf stat sleep 10
Performance counter statistics:

     545,144,267  cpu-cycles         # 0.054173 GHz                      (12%)
     307,576,139  instructions       # 1.772388 cycles per instruction   (12%)
       2,657,986  branch-misses      # 264.133 K/sec                     (12%)
  376.753066(ms)  task-clock         # 3.743928% cpu usage               (12%)
              64  context-switches   # 6.360 /sec                        (12%)
           5,002  page-faults        # 497.066 /sec                      (12%)

Total test time: 10.063044 seconds.
```

系统默认创建了6种event来跟踪统计“sleep 10”命令的执行情况，这里只会使用read()调用来读取perf_event的count数据，没有使用mmap创建ringbuffer所有没有sample数据。

我们也可以自定义选项来使用命令：

```
 # simpleperf help stat
Usage: simpleperf stat [options] [command [command-args]]
    Gather performance counter information of running [command].
    -a           Collect system-wide information.
    --cpu cpu_item1,cpu_item2,...
                 Collect information only on the selected cpus. cpu_item can
                 be a cpu number like 1, or a cpu range like 0-3.
    -e event1[:modifier1],event2[:modifier2],...
                 Select the event list to count. Use `simpleperf list` to find
                 all possible event names. Modifiers can be added to define
                 how the event should be monitored. Possible modifiers are:
                   u - monitor user space events only
                   k - monitor kernel space events only
    --no-inherit
                 Don't stat created child threads/processes.
    -p pid1,pid2,...
                 Stat events on existing processes. Mutually exclusive with -a.
    -t tid1,tid2,...
                 Stat events on existing threads. Mutually exclusive with -a.
    --verbose    Show result in verbose mode.

 #
```

stat子命令的实现主体在StatCommand的Run方法中，system/extras/simpleperf/cmd_stat.cpp:

```
bool StatCommand::Run(const std::vector<std::string>& args) {
  if (!CheckPerfEventLimit()) {
    return false;
  }

  // 1. Parse options, and use default measured event types if not given.
  /* (1) 解析"simpleperf stat xxx"中的参数，具体有哪些参数参考"simpleperf help stat"命令 */
  std::vector<std::string> workload_args;
  if (!ParseOptions(args, &workload_args)) {
    return false;
  }
  
  /* (1.1) 如果没有使用"-e xxx"选项来指定event，系统给你指定默认的event */
  if (measured_event_types_.empty()) {
    if (!AddDefaultMeasuredEventTypes()) {
      return false;
    }
  }
  
  /* (1.2) 把指定的events和其他选项进行合法性判断，并且封装成标准的attr保存到selections_中 */
  if (!SetEventSelection()) {
    return false;
  }

  // 2. Create workload.
  /* (2) 创建需要监控的子进程，但是子进程不会马上进行exec操作，它等待pipe信号同步
    在后面调用workload->Start()后，才会进行exec操作
   */
  std::unique_ptr<Workload> workload;
  if (!workload_args.empty()) {
    workload = Workload::CreateWorkload(workload_args);
    if (workload == nullptr) {
      return false;
    }
  }
  if (!system_wide_collection_ && monitored_threads_.empty()) {
    if (workload != nullptr) {
      monitored_threads_.push_back(workload->GetPid());
      event_selection_set_.SetEnableOnExec(true);
    } else {
      LOG(ERROR) << "No threads to monitor. Try `simpleperf help stat` for help\n";
      return false;
    }
  }

  // 3. Open perf_event_files.
  /* (3) 根据cpu、pid、event组合，创建多个perf_event */
  if (system_wide_collection_) {
    if (!event_selection_set_.OpenEventFilesForCpus(cpus_)) {
      return false;
    }
  } else {
    if (!event_selection_set_.OpenEventFilesForThreadsOnCpus(monitored_threads_, cpus_)) {
      return false;
    }
  }

  // 4. Count events while workload running.
  /* (4) 通知workload开始执行exec */
  auto start_time = std::chrono::steady_clock::now();
  if (workload != nullptr && !workload->Start()) {
    return false;
  }
  /* 子进程执行完成后使用SIGCHLD信号通知父进程 */
  while (!signaled) {
    sleep(1);
  }
  auto end_time = std::chrono::steady_clock::now();

  // 5. Read and print counters.
  /* (5) 在workload执行完成后，逐个读出perf_event的count值，归类累加并展示 */
  std::vector<CountersInfo> counters;
  if (!event_selection_set_.ReadCounters(&counters)) {
    return false;
  }
  double duration_in_sec =
      std::chrono::duration_cast<std::chrono::duration<double>>(end_time - start_time).count();
  if (!ShowCounters(counters, duration_in_sec)) {
    return false;
  }
  return true;
}
```

如果不使用"-e xxx"指定event，系统会默认指定event，并且判断当前系统能支持哪些event。合法event加入到measured_event_types_中：

```
bool StatCommand::AddDefaultMeasuredEventTypes() {

  /* (1.1.1) 默认属性在default_measured_event_types中定义 */
  for (auto& name : default_measured_event_types) {
  
    // It is not an error when some event types in the default list are not supported by the kernel.
    /* (1.1.2) 根据name在全集中找到"type+config" */
    const EventType* type = FindEventTypeByName(name);
    
    /* (1.1.3) 使用默认属性调用perf_event_open()，如果可以有效返回，说明本系统支持 */
    if (type != nullptr && IsEventAttrSupportedByKernel(CreateDefaultPerfEventAttr(*type))) {
    
      /* (1.1.4) 加入到measured_event_types_ */
      AddMeasuredEventType(name);
    }
  }
  if (measured_event_types_.empty()) {
    LOG(ERROR) << "Failed to add any supported default measured types";
    return false;
  }
  return true;
}

static std::vector<std::string> default_measured_event_types{
    "cpu-cycles",   "stalled-cycles-frontend", "stalled-cycles-backend",
    "instructions", "branch-instructions",     "branch-misses",
    "task-clock",   "context-switches",        "page-faults",
};

```

把measured_event_types_中的event和其他选项进行组合，合法的加入到selections_中：

```
bool StatCommand::SetEventSelection() {
  for (auto& event_type : measured_event_types_) {
    if (!event_selection_set_.AddEventType(event_type)) {
      return false;
    }
  }
  event_selection_set_.SetInherit(child_inherit_);
  return true;
}

|→

bool EventSelectionSet::AddEventType(const EventTypeAndModifier& event_type_modifier) {
  EventSelection selection;
  
  /* (1.2.1) 将event和modifier组合 */
  selection.event_type_modifier = event_type_modifier;
  selection.event_attr = CreateDefaultPerfEventAttr(event_type_modifier.event_type);
  selection.event_attr.exclude_user = event_type_modifier.exclude_user;
  selection.event_attr.exclude_kernel = event_type_modifier.exclude_kernel;
  selection.event_attr.exclude_hv = event_type_modifier.exclude_hv;
  selection.event_attr.exclude_host = event_type_modifier.exclude_host;
  selection.event_attr.exclude_guest = event_type_modifier.exclude_guest;
  selection.event_attr.precise_ip = event_type_modifier.precise_ip;
  
  /* (1.2.2) 使用perf_event_open()来继续合法性判断 */
  if (!IsEventAttrSupportedByKernel(selection.event_attr)) {
    LOG(ERROR) << "Event type '" << event_type_modifier.name << "' is not supported by the kernel";
    return false;
  }
  
  /* (1.2.3) 保存到selections_中 */
  selections_.push_back(std::move(selection));
  UnionSampleType();
  return true;
}

```

我们在给workload创建子进程时使用了pipe机制用来同步：

```
std::unique_ptr<Workload> Workload::CreateWorkload(const std::vector<std::string>& args) {
  std::unique_ptr<Workload> workload(new Workload(args));
  if (workload != nullptr && workload->CreateNewProcess()) {
    return workload;
  }
  return nullptr;
}

|→

bool Workload::CreateNewProcess() {
  CHECK_EQ(work_state_, NotYetCreateNewProcess);

  /* pipe函数返回2个fd：fd[0]负责读，fd[1]负责写。 */

  /* (2.1.1) 子进程开始执行exce的信号：父进程写，子进程读*/
  int start_signal_pipe[2];
  if (pipe2(start_signal_pipe, O_CLOEXEC) != 0) {
    PLOG(ERROR) << "pipe2() failed";
    return false;
  }

  /* (2.1.2) 子进程执行出错的信号：子进程写，父进程读*/
  int exec_child_pipe[2];
  if (pipe2(exec_child_pipe, O_CLOEXEC) != 0) {
    PLOG(ERROR) << "pipe2() failed";
    close(start_signal_pipe[0]);
    close(start_signal_pipe[1]);
    return false;
  }

  pid_t pid = fork();
  if (pid == -1) {
    PLOG(ERROR) << "fork() failed";
    close(start_signal_pipe[0]);
    close(start_signal_pipe[1]);
    close(exec_child_pipe[0]);
    close(exec_child_pipe[1]);
    return false;
  } else if (pid == 0) {
    // In child process.
    close(start_signal_pipe[1]);
    close(exec_child_pipe[0]);
    
    /* (2.1.3) 子进程的处理，准备exec执行workload */
    ChildProcessFn(args_, start_signal_pipe[0], exec_child_pipe[1]);
    _exit(0);
  }
  // In parent process.
  close(start_signal_pipe[0]);
  close(exec_child_pipe[1]);
  start_signal_fd_ = start_signal_pipe[1];
  exec_child_fd_ = exec_child_pipe[0];
  work_pid_ = pid;
  work_state_ = NotYetStartNewProcess;
  return true;
}

||→

static void ChildProcessFn(std::vector<std::string>& args, int start_signal_fd, int exec_child_fd) {
  std::vector<char*> argv(args.size() + 1);
  for (size_t i = 0; i < args.size(); ++i) {
    argv[i] = &args[i][0];
  }
  argv[args.size()] = nullptr;

  char start_signal = 0;
  
  /* (2.1.3.1) 暂停，等待父进程的开始信号 */
  ssize_t nread = TEMP_FAILURE_RETRY(read(start_signal_fd, &start_signal, 1));
  
  if (nread == 1 && start_signal == 1) {
    close(start_signal_fd);
    
    /* (2.1.3.2) exec执行workload */
    execvp(argv[0], argv.data());
    // If execvp() succeed, we will not arrive here. But if it failed, we need to
    // report the failure to the parent process by writing 1 to exec_child_fd.
    int saved_errno = errno;
    char exec_child_failed = 1;
    
    /* (2.1.3.3) 如果exec执行失败，通知父进程 */
    TEMP_FAILURE_RETRY(write(exec_child_fd, &exec_child_failed, 1));
    close(exec_child_fd);
    errno = saved_errno;
    PLOG(ERROR) << "child process failed to execvp(" << argv[0] << ")";
  } else {
    PLOG(ERROR) << "child process failed to receive start_signal, nread = " << nread;
  }
}
```

为了perf_event和workload之间的同步，我们设置perf_event的EnableOnExec属性：

```
void EventSelectionSet::SetEnableOnExec(bool enable) {
  for (auto& selection : selections_) {
    // If sampling is enabled on exec, then it is disabled at startup, otherwise
    // it should be enabled at startup. Don't use ioctl(PERF_EVENT_IOC_ENABLE)
    // to enable it after perf_event_open(). Because some android kernels can't
    // handle ioctl() well when cpu-hotplug happens. See http://b/25193162.
    
    /* (2.2) 设置perf_event的enable_on_exec属性，可以从"perf_event内核框架"一章中查看其原理 */
    if (enable) {
      selection.event_attr.enable_on_exec = 1;
      selection.event_attr.disabled = 1;
    } else {
      selection.event_attr.enable_on_exec = 0;
      selection.event_attr.disabled = 0;
    }
  }
}
```

一条命令可能会创建多个perf_event。因为cpu、pid、event的组合，需要多个perf_event才能满足：

```
bool EventSelectionSet::OpenEventFilesForThreadsOnCpus(const std::vector<pid_t>& threads,
                                                       std::vector<int> cpus) {
  /* (3.1) 对cpu参数的合法性判断 */
  if (!cpus.empty()) {
    if (!CheckIfCpusOnline(cpus)) {
      return false;
    }
  } else {
    cpus = GetOnlineCpus();
  }
  
  /* (3.2)  */
  return OpenEventFiles(threads, cpus);
}

|→

bool EventSelectionSet::OpenEventFiles(const std::vector<pid_t>& threads,
                                       const std::vector<int>& cpus) {
  
  /* (3.2.1) 组合event/tid/cpu，逐个创建perf_event */
  for (auto& selection : selections_) {
    for (auto& tid : threads) {
      size_t open_per_thread = 0;
      for (auto& cpu : cpus) {
        
        /* (3.2.2) 创建perf_event */
        auto event_fd = EventFd::OpenEventFile(selection.event_attr, tid, cpu);
        if (event_fd != nullptr) {
          LOG(VERBOSE) << "OpenEventFile for tid " << tid << ", cpu " << cpu;
          
          /* (3.2.3) 保存fd到selection.event_fds */
          selection.event_fds.push_back(std::move(event_fd));
          ++open_per_thread;
        }
      }
      // As the online cpus can be enabled or disabled at runtime, we may not open event file for
      // all cpus successfully. But we should open at least one cpu successfully.
      if (open_per_thread == 0) {
        PLOG(ERROR) << "failed to open perf event file for event_type "
                    << selection.event_type_modifier.name << " for "
                    << (tid == -1 ? "all threads" : android::base::StringPrintf(" thread %d", tid));
        return false;
      }
    }
  }
  return true;
}
```

perf_event创建完成以后，通知workload开始exec：

```
bool Workload::Start() {
  CHECK_EQ(work_state_, NotYetStartNewProcess);
  char start_signal = 1;
  
  /* (4.1) 写入start_signal_fd_，通知子进程开始exec workload */
  ssize_t nwrite = TEMP_FAILURE_RETRY(write(start_signal_fd_, &start_signal, 1));
  if (nwrite != 1) {
    PLOG(ERROR) << "write start signal failed";
    return false;
  }
  char exec_child_failed;
  
  /* (4.2) 如果收到exec_child_fd_信息，说明子进程exec出错 */
  ssize_t nread = TEMP_FAILURE_RETRY(read(exec_child_fd_, &exec_child_failed, 1));
  if (nread != 0) {
    if (nread == -1) {
      PLOG(ERROR) << "failed to receive error message from child process";
    } else {
      LOG(ERROR) << "received error message from child process";
    }
    return false;
  }
  work_state_ = Started;
  return true;
}
```

workload执行完成后，根据event逐个perf_event读出其count值：

```
bool EventSelectionSet::ReadCounters(std::vector<CountersInfo>* counters) {
  counters->clear();
  for (auto& selection : selections_) {
    CountersInfo counters_info;
    counters_info.event_type = &selection.event_type_modifier;
    for (auto& event_fd : selection.event_fds) {
      CountersInfo::CounterInfo counter_info;
      
      /* (5.1) 读出当前perf_event的count值 */
      if (!event_fd->ReadCounter(&counter_info.counter)) {
        return false;
      }
      counter_info.tid = event_fd->ThreadId();
      counter_info.cpu = event_fd->Cpu();
      counters_info.counters.push_back(counter_info);
    }
    counters->push_back(counters_info);
  }
  return true;
}

|→

bool EventFd::ReadCounter(PerfCounter* counter) const {
  CHECK(counter != nullptr);
  if (!android::base::ReadFully(perf_event_fd_, counter, sizeof(*counter))) {
    PLOG(ERROR) << "ReadCounter from " << Name() << " failed";
    return false;
  }
  return true;
}
```

再统计这些count，以报告的形式呈现出来：

```
bool StatCommand::ShowCounters(const std::vector<CountersInfo>& counters, double duration_in_sec) {
  printf("Performance counter statistics:\n\n");

  /* (5.2.1) verbose打印出明显 */
  if (verbose_mode_) {
    for (auto& counters_info : counters) {
      const EventTypeAndModifier* event_type = counters_info.event_type;
      for (auto& counter_info : counters_info.counters) {
        printf("%s(tid %d, cpu %d): count %s, time_enabled %" PRIu64 ", time running %" PRIu64
               ", id %" PRIu64 "\n",
               event_type->name.c_str(), counter_info.tid, counter_info.cpu,
               ReadableCountValue(counter_info.counter.value, *event_type).c_str(),
               counter_info.counter.time_enabled, counter_info.counter.time_running,
               counter_info.counter.id);
      }
    }
  }

  std::vector<CounterSummary> summaries;
  
  /* (5.2.2) 按照event type逐个遍历 */
  for (auto& counters_info : counters) {
    uint64_t value_sum = 0;
    uint64_t time_enabled_sum = 0;
    uint64_t time_running_sum = 0;
    for (auto& counter_info : counters_info.counters) {
    
      /* (5.2.2.1) 按照type，累加count/enbale时间/running时间 */
      value_sum += counter_info.counter.value;
      time_enabled_sum += counter_info.counter.time_enabled;
      time_running_sum += counter_info.counter.time_running;
    }
    double scale = 1.0;
    uint64_t scaled_count = value_sum;
    if (time_running_sum < time_enabled_sum) {
      if (time_running_sum == 0) {
        scaled_count = 0;
      } else {
      
        /* (5.2.2.2) 比例 = enbale时间/running时间 */
        scale = static_cast<double>(time_enabled_sum) / time_running_sum;
        scaled_count = static_cast<uint64_t>(scale * value_sum);
      }
    }
    CounterSummary summary;
    summary.event_type = counters_info.event_type;
    summary.count = scaled_count;
    summary.scale = scale;
    
    /* (5.2.2.3) 把count值转成可读字符串 */
    summary.readable_count_str = ReadableCountValue(summary.count, *summary.event_type);
    summaries.push_back(summary);
  }


  /* (5.2.2.4) 获取每种type的comment */
  for (auto& summary : summaries) {
    summary.comment = GetCommentForSummary(summary, summaries, duration_in_sec);
  }

  size_t count_column_width = 0;
  size_t name_column_width = 0;
  size_t comment_column_width = 0;
  /* (5.2.2.5) 计算每个字段的最大值，用来对齐 */
  for (auto& summary : summaries) {
    count_column_width = std::max(count_column_width, summary.readable_count_str.size());
    name_column_width = std::max(name_column_width, summary.event_type->name.size());
    comment_column_width = std::max(comment_column_width, summary.comment.size());
  }

  /* (5.2.2.6) 轮询event的type，打印出其统计值 */
  for (auto& summary : summaries) {
    printf("  %*s  %-*s   # %-*s   (%.0lf%%)\n", static_cast<int>(count_column_width),
           summary.readable_count_str.c_str(), static_cast<int>(name_column_width),
           summary.event_type->name.c_str(), static_cast<int>(comment_column_width),
           summary.comment.c_str(), 1.0 / summary.scale * 100);
  }

  printf("\nTotal test time: %lf seconds.\n", duration_in_sec);
  return true;
}
```

# 4、record子命令

我们可以使用“simpleperf record xxx”命令记录一个命令的详细trace数据，在执行“xxx”命令的过程中把count数据和trace数据保存到perf.data中，随后可以使用 report子命令进行分析。

```
/sdcard # simpleperf record sleep 10
/sdcard #
/sdcard # ls -l perf.data
-rw-rw---- 1 root sdcard_rw 10264 1970-02-27 08:27 perf.data
/sdcard #
/sdcard # simpleperf report
simpleperf W  9131  9131 dso.cpp:263] Symbol addresses in /proc/kallsyms are all zero. Check /proc/sys/kernel/kptr_restrict if possible.
Cmdline: /system/xbin/simpleperf record sleep 10
Samples: 131 of event 'cpu-cycles'
Event count: 40889310

Overhead  Command     Pid   Tid   Shared Object          Symbol
70.02%    sleep       9078  9078  [kernel.kallsyms]      unknown
10.78%    sleep       9078  9078  /system/bin/linker64   [linker]soinfo::gnu_lookup(SymbolName&, version_info const*, unsigned int*) const
3.96%     sleep       9078  9078  /system/bin/linker64   [linker]soinfo_do_lookup(soinfo*, char const*, version_info const*, soinfo**, LinkedList<soinfo, SoinfoListAllocator> const&, LinkedList<soinfo, SoinfoListAllocator> const&, elf64_sym const**)
3.35%     sleep       9078  9078  /system/bin/linker64   [linker]isspace
2.66%     sleep       9078  9078  /system/bin/linker64   [linker]strcmp
1.38%     sleep       9078  9078  /system/bin/linker64   [linker]memset
1.34%     sleep       9078  9078  /system/lib64/libc.so  pthread_mutex_unlock
1.33%     sleep       9078  9078  /system/lib64/libc.so  memcpy
1.32%     sleep       9078  9078  /system/lib64/libc.so  extent_szad_comp
1.31%     sleep       9078  9078  /system/bin/linker64   [linker]VersionTracker::init_verdef(soinfo const*)
1.28%     sleep       9078  9078  /system/bin/linker64   [linker]bool soinfo::relocate<plain_reloc_iterator>(VersionTracker const&, plain_reloc_iterator&&, LinkedList<soinfo, SoinfoListAllocator> const&, LinkedList<soinfo, SoinfoListAllocator> const&)
1.25%     sleep       9078  9078  /system/bin/linker64   [linker]soinfo::elf_lookup(SymbolName&, version_info const*, unsigned int*) const
0.01%     simpleperf  9078  9078  [kernel.kallsyms]      unknown

```

系统默认创建了6种event来跟踪统计“sleep 10”命令的执行情况，这里会使mmap创建ringbuffer来保存sample数据，并记录到文件中。

我们也可以自定义选项来使用命令：

```
# simpleperf help record
Usage: simpleperf record [options] [command [command-args]]
    Gather sampling information when running [command].
    -a           System-wide collection.
    -b           Enable take branch stack sampling. Same as '-j any'
    -c count     Set event sample period.
    --call-graph fp | dwarf[,<dump_stack_size>]
                 Enable call graph recording. Use frame pointer or dwarf as the
                 method to parse call graph in stack. Default is dwarf,8192.
    --cpu cpu_item1,cpu_item2,...
                 Collect samples only on the selected cpus. cpu_item can be cpu
                 number like 1, or cpu range like 0-3.
    -e event1[:modifier1],event2[:modifier2],...
                 Select the event list to sample. Use `simpleperf list` to find
                 all possible event names. Modifiers can be added to define
                 how the event should be monitored. Possible modifiers are:
                   u - monitor user space events only
                   k - monitor kernel space events only
    -f freq      Set event sample frequency.
    -F freq      Same as '-f freq'.
    -g           Same as '--call-graph dwarf'.
    -j branch_filter1,branch_filter2,...
                 Enable taken branch stack sampling. Each sample
                 captures a series of consecutive taken branches.
                 The following filters are defined:
                   any: any type of branch
                   any_call: any function call or system call
                   any_ret: any function return or system call return
                   ind_call: any indirect branch
                   u: only when the branch target is at the user level
                   k: only when the branch target is in the kernel
                 This option requires at least one branch type among any,
                 any_call, any_ret, ind_call.
    -m mmap_pages
                 Set the size of the buffer used to receiving sample data from
                 the kernel. It should be a power of 2. The default value is 16.
    --no-inherit
                 Don't record created child threads/processes.
    --no-unwind  If `--call-graph dwarf` option is used, then the user's stack will
                 be unwound by default. Use this option to disable the unwinding of
                 the user's stack.
    -o record_file_name    Set record file name, default is perf.data.
    -p pid1,pid2,...
                 Record events on existing processes. Mutually exclusive with -a.
    --post-unwind
                 If `--call-graph dwarf` option is used, then the user's stack will
                 be unwound while recording by default. But it may lose records as
                 stacking unwinding can be time consuming. Use this option to unwind
                 the user's stack after recording.
    -t tid1,tid2,...
                 Record events on existing threads. Mutually exclusive with -a.
```

record子命令的实现主体在RecordCommand的Run方法中，基本流程和stat子命令类似多了mmap操作，system/extras/simpleperf/cmd_record.cpp:


```
bool RecordCommand::Run(const std::vector<std::string>& args) {
  if (!CheckPerfEventLimit()) {
    return false;
  }

  // 1. Parse options, and use default measured event type if not given.
  /* (1) 解析"simpleperf record xxx"中的参数，具体有哪些参数参考"simpleperf help stat"命令 */
  std::vector<std::string> workload_args;
  if (!ParseOptions(args, &workload_args)) {
    return false;
  }
  
  /* (1.1) 如果没有使用"-e xxx"选项来指定event，系统给你指定默认的event */
  if (measured_event_types_.empty()) {
    if (!AddMeasuredEventType(default_measured_event_type)) {
      return false;
    }
  }
  /* (1.2) 把指定的events和其他选项进行合法性判断，并且封装成标准的attr保存到selections_中 */
  if (!SetEventSelection()) {
    return false;
  }

  // 2. Create workload.
  /* (2) 创建workload */
  std::unique_ptr<Workload> workload;
  if (!workload_args.empty()) {
    /* (2.1) 创建需要监控的子进程，但是子进程不会马上进行exec操作，它等待pipe信号同步
      在后面调用workload->Start()后，才会进行exec操作
      来保证父进程和workload的同步
     */
    workload = Workload::CreateWorkload(workload_args);
    if (workload == nullptr) {
      return false;
    }
  }
  if (!system_wide_collection_ && monitored_threads_.empty()) {
    if (workload != nullptr) {
      monitored_threads_.push_back(workload->GetPid());
      
      /* (2.2) 如果是监控进程，会把perf_event的enable_on_exec属性置位，来保证perf_event和workload的启动同步 */
      event_selection_set_.SetEnableOnExec(true);
    } else {
      LOG(ERROR) << "No threads to monitor. Try `simpleperf help record` for help\n";
      return false;
    }
  }

  // 3. Open perf_event_files, create memory mapped buffers for perf_event_files, add prepare poll
  //    for perf_event_files.
  /* (3) 根据cpu、pid、event组合，创建多个perf_event */
  if (system_wide_collection_) {
    if (!event_selection_set_.OpenEventFilesForCpus(cpus_)) {
      system_wide_perf_event_open_failed = true;
      return false;
    }
  } else {
    /* (3.1) 创建perf_event对应的fd */
    if (!event_selection_set_.OpenEventFilesForThreadsOnCpus(monitored_threads_, cpus_)) {
      return false;
    }
  }
  
  /* (3.2) 通过fd做mmap操作，给perf_event分配ringbuffer 
     默认perf_mmap_pages_ = 16
   */
  if (!event_selection_set_.MmapEventFiles(perf_mmap_pages_)) {
    return false;
  }
  std::vector<pollfd> pollfds;
  /* (3.3) 聚合fd，用来做poll操作 */
  event_selection_set_.PreparePollForEventFiles(&pollfds);

  // 4. Create perf.data.
  /* (4) 创建perf.data文件，并且记录系统信息 */
  if (!CreateAndInitRecordFile()) {
    return false;
  }

  // 5. Write records in mmap buffers of perf_event_files to output file while workload is running.
  /* (5) 记录workload运行中perf_event的sample信息 */
  if (workload != nullptr && !workload->Start()) {
    return false;
  }
  
  /* (5.1) 创建record cache */
  record_cache_.reset(
      new RecordCache(*event_selection_set_.FindEventAttrByType(measured_event_types_[0])));
  auto callback = std::bind(&RecordCommand::CollectRecordsFromKernel, this, std::placeholders::_1,
                            std::placeholders::_2);
  /* (5.2) 通过poll操作查询数据，记录mmap数据到cache中 */
  while (true) {
    if (!event_selection_set_.ReadMmapEventData(callback)) {
      return false;
    }
    
    /* (5.3) workload执行完成，退出 */
    if (signaled) {
      break;
    }
    poll(&pollfds[0], pollfds.size(), -1);
  }
  
  /* (5.4) 从cache中读数据，记录到perf.data文件中 */
  std::vector<std::unique_ptr<Record>> records = record_cache_->PopAll();
  for (auto& r : records) {
    if (!ProcessRecord(r.get())) {
      return false;
    }
  }

  // 6. Dump additional features, and close record file.
  /* (6) dump更多的信息到文件中 */
  if (!DumpAdditionalFeatures(args)) {
    return false;
  }
  if (!record_file_writer_->Close()) {
    return false;
  }

  // 7. Unwind dwarf callchain.
  /* (7) 展开dwarf调用链 */
  if (post_unwind_) {
    if (!PostUnwind(args)) {
      return false;
    }
  }
  LOG(VERBOSE) << "Record " << sample_record_count_ << " samples.";
  return true;
}

```

mmap操作的具体实现：

```
bool EventSelectionSet::MmapEventFiles(size_t mmap_pages) {
  for (auto& selection : selections_) {
    for (auto& event_fd : selection.event_fds) {
      if (!event_fd->MmapContent(mmap_pages)) {
        return false;
      }
    }
  }
  return true;
}

|→

bool EventFd::MmapContent(size_t mmap_pages) {
  CHECK(IsPowerOfTwo(mmap_pages));
  size_t page_size = sysconf(_SC_PAGE_SIZE);
  size_t mmap_len = (mmap_pages + 1) * page_size;
  
  /* (3.2.1) mmap系统调用 */
  void* mmap_addr = mmap(nullptr, mmap_len, PROT_READ | PROT_WRITE, MAP_SHARED, perf_event_fd_, 0);
  if (mmap_addr == MAP_FAILED) {
    PLOG(ERROR) << "mmap() failed for " << Name();
    return false;
  }
  mmap_addr_ = mmap_addr;
  mmap_len_ = mmap_len;
  mmap_metadata_page_ = reinterpret_cast<perf_event_mmap_page*>(mmap_addr_);
  mmap_data_buffer_ = reinterpret_cast<char*>(mmap_addr_) + page_size;
  mmap_data_buffer_size_ = mmap_len_ - page_size;
  if (data_process_buffer_.size() < mmap_data_buffer_size_) {
    data_process_buffer_.resize(mmap_data_buffer_size_);
  }
  return true;
}
```

在创建perf.data文件时，还保存了不少系统信息：

```
bool RecordCommand::CreateAndInitRecordFile() {
  
  /* (4.1) 创建perf.data文件并记录perf_event的fd信息 */
  record_file_writer_ = CreateRecordFile(record_filename_);
  if (record_file_writer_ == nullptr) {
    return false;
  }
  
  /* (4.2) dump kernel和module信息到文件 */
  if (!DumpKernelAndModuleMmaps()) {
    return false;
  }
  
  /* (4.3) dump 进程信息到文件 */
  if (!DumpThreadCommAndMmaps(system_wide_collection_, monitored_threads_)) {
    return false;
  }
  return true;
}

|→

std::unique_ptr<RecordFileWriter> RecordCommand::CreateRecordFile(const std::string& filename) {

  /* (4.1.1) 创建perf.data文件 */
  std::unique_ptr<RecordFileWriter> writer = RecordFileWriter::CreateInstance(filename);
  if (writer == nullptr) {
    return nullptr;
  }

  /* (4.1.2) 记录perf_event的fd信息到文件 */
  std::vector<AttrWithId> attr_ids;
  for (auto& event_type : measured_event_types_) {
    AttrWithId attr_id;
    attr_id.attr = event_selection_set_.FindEventAttrByType(event_type);
    CHECK(attr_id.attr != nullptr);
    const std::vector<std::unique_ptr<EventFd>>* fds =
        event_selection_set_.FindEventFdsByType(event_type);
    CHECK(fds != nullptr);
    for (auto& fd : *fds) {
      attr_id.ids.push_back(fd->Id());
    }
    attr_ids.push_back(attr_id);
  }
  if (!writer->WriteAttrSection(attr_ids)) {
    return nullptr;
  }
  return writer;
}
```

通过ReadMmapEventData()函数读取ringbuffer数据，并且通过回调CollectRecordsFromKernel()函数记录到cache中：

```
bool EventSelectionSet::ReadMmapEventData(std::function<bool(const char*, size_t)> callback) {
  for (auto& selection : selections_) {
    for (auto& event_fd : selection.event_fds) {
      while (true) {
        bool have_data;
        
        /* (5.2.1) 逐个perf_event读取ringbuffer数据 */
        if (!ReadMmapEventDataForFd(event_fd, callback, &have_data)) {
          return false;
        }
        if (!have_data) {
          break;
        }
      }
    }
  }
  return true;
}

|→

static bool ReadMmapEventDataForFd(std::unique_ptr<EventFd>& event_fd,
                                   std::function<bool(const char*, size_t)> callback,
                                   bool* have_data) {
  *have_data = false;
  while (true) {
    char* data;
    size_t size = event_fd->GetAvailableMmapData(&data);
    if (size == 0) {
      break;
    }
    if (!callback(data, size)) {
      return false;
    }
    *have_data = true;
  }
  return true;
}

||→

size_t EventFd::GetAvailableMmapData(char** pdata) {
  // The mmap_data_buffer is used as a ring buffer like below. The kernel continuously writes
  // records to the buffer, and the user continuously read records out.
  //         _________________________________________
  // buffer | can write   |   can read   |  can write |
  //                      ^              ^
  //                    read_head       write_head
  //
  // So the user can read records in [read_head, write_head), and the kernel can write records
  // in [write_head, read_head). The kernel is responsible for updating write_head, and the user
  // is responsible for updating read_head.

  size_t buf_mask = mmap_data_buffer_size_ - 1;
  size_t write_head = static_cast<size_t>(mmap_metadata_page_->data_head & buf_mask);
  size_t read_head = static_cast<size_t>(mmap_metadata_page_->data_tail & buf_mask);

  if (read_head == write_head) {
    // No available data.
    return 0;
  }

  // Make sure we can see the data after the fence.
  std::atomic_thread_fence(std::memory_order_acquire);

  // Copy records from mapped buffer to data_process_buffer. Note that records can be wrapped
  // at the end of the mapped buffer.
  char* to = data_process_buffer_.data();
  if (read_head < write_head) {
    char* from = mmap_data_buffer_ + read_head;
    size_t n = write_head - read_head;
    memcpy(to, from, n);
    to += n;
  } else {
    char* from = mmap_data_buffer_ + read_head;
    size_t n = mmap_data_buffer_size_ - read_head;
    memcpy(to, from, n);
    to += n;
    from = mmap_data_buffer_;
    n = write_head;
    memcpy(to, from, n);
    to += n;
  }
  size_t read_bytes = to - data_process_buffer_.data();
  *pdata = data_process_buffer_.data();
  DiscardMmapData(read_bytes);
  return read_bytes;
}
```

# 5、report子命令

暂不分析。
