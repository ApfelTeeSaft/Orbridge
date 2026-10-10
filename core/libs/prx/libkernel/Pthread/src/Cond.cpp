#include "prx/libkernel/Pthread/include/Pthread.hpp"
#include "prx/libkernel/Pthread/include/Mutex.hpp"
#include "prx/libkernel/Pthread/include/Cond.hpp"
#include "prx/libkernel/Pthread/Posix/Common.hpp"
#include "prx/libkernel/Time/include/Time.hpp"
#include "prx/libkernel/Time/include/TimedWait.hpp"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <thread>
#include <stop_token>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#ifdef _WIN32
#include <windows.h>
#endif

namespace {

constexpr int sceTimedOut = static_cast<int>(0x8002003cu);
std::mutex condInitializationMutex;

// Debug aid: APS5_TRACE_COND_PENDING=1 observes outstanding guest condition
// waits without changing their wait deadlines or notification semantics.
bool tracePendingConds() {
    static const bool enabled = [] {
        const char* value = std::getenv("APS5_TRACE_COND_PENDING");
        return value && *value && !(value[0] == '0' && value[1] == '\0');
    }();
    return enabled;
}

struct PendingCondWait {
    std::uint32_t tid = 0;
    const void* condition = nullptr;
    const void* mutex = nullptr;
    const void* caller = nullptr;
    std::chrono::steady_clock::time_point since;
    int recursion = 0;
};

struct CondWaitMonitor {
    std::mutex mutex;
    std::unordered_map<std::uint32_t, PendingCondWait> waits;
    std::jthread reporter;

    CondWaitMonitor() : reporter([this](std::stop_token stop) {
        while (!stop.stop_requested()) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            if (stop.stop_requested()) break;
            const auto now = std::chrono::steady_clock::now();
            std::vector<PendingCondWait> pending;
            {
                std::lock_guard lock(mutex);
                for (const auto& [tid, wait] : waits) {
                    if (now - wait.since >= std::chrono::seconds(10)) pending.push_back(wait);
                }
            }
            if (pending.empty()) continue;
            std::sort(pending.begin(), pending.end(), [](const auto& a, const auto& b) {
                return a.since < b.since;
            });
            std::fprintf(stderr, "[cond.pending] outstanding=%zu (>=10s)\n", pending.size());
            for (std::size_t i = 0; i < pending.size() && i < 24; ++i) {
                const auto& wait = pending[i];
                const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - wait.since).count();
                std::fprintf(stderr,
                    "[cond.pending] tid=%u duration_ms=%lld cond=%p mutex=%p caller=%p recursion=%d\n",
                    static_cast<unsigned>(wait.tid), static_cast<long long>(elapsed),
                    wait.condition, wait.mutex, wait.caller, wait.recursion);
            }
            if (pending.size() > 24) std::fprintf(stderr, "[cond.pending] ... additional waits omitted\n");
            std::fflush(stderr);
        }
    }) {}
};

CondWaitMonitor& condWaitMonitor() {
    static CondWaitMonitor monitor;
    return monitor;
}

struct PendingCondRegistration {
    std::uint32_t tid = 0;
    PendingCondRegistration(const void* cond, const void* mutex, const void* caller, int recursion) {
#ifdef _WIN32
        tid = static_cast<std::uint32_t>(GetCurrentThreadId());
#else
        tid = static_cast<std::uint32_t>(std::hash<std::thread::id>{}(std::this_thread::get_id()));
#endif
        auto& monitor = condWaitMonitor();
        std::lock_guard lock(monitor.mutex);
        monitor.waits[tid] = PendingCondWait{tid, cond, mutex, caller, std::chrono::steady_clock::now(), recursion};
    }
    ~PendingCondRegistration() {
        auto& monitor = condWaitMonitor();
        std::lock_guard lock(monitor.mutex);
        monitor.waits.erase(tid);
    }
    PendingCondRegistration(const PendingCondRegistration&) = delete;
    PendingCondRegistration& operator=(const PendingCondRegistration&) = delete;
};

PthreadCond destroyedCond() {
    return reinterpret_cast<PthreadCond>(std::uintptr_t{2});
}

PthreadCond resolveCond(PthreadCond* cond) {
    if (!cond)
        throw std::invalid_argument("Condition variable pointer is null");
    std::atomic_ref<PthreadCond> slot(*cond);
    if (const auto current = slot.load(std::memory_order_acquire); current && current != destroyedCond())
        return current;
    std::lock_guard lock(condInitializationMutex);
    const auto current = slot.load(std::memory_order_acquire);
    if (current == destroyedCond())
        throw std::runtime_error("Condition variable has been destroyed");
    if (current)
        return current;
    auto* created = new PthreadCondPrivate();
    slot.store(created, std::memory_order_release);
    return created;
}

PthreadMutex lockedMutex(PthreadMutex* mutex) {
    if (!mutex || !*mutex)
        throw std::invalid_argument("Mutex pointer is null");
    auto* current = *mutex;
    if (current->_owner.load(std::memory_order_acquire) != std::this_thread::get_id())
        throw std::runtime_error("Condition wait mutex is not owned by the current thread");
    return current;
}

int waitUntil(PthreadCond* cond, PthreadMutex* mutex, std::optional<std::uint64_t> deadlineNanos, const void* caller) {
    auto* c = resolveCond(cond);
    auto* m = lockedMutex(mutex);
    std::optional<PendingCondRegistration> pending;
    if (tracePendingConds()) {
        pending.emplace(c, m, caller, m->_type == MutexType::Recursive ? m->_count : 1);
    }
    bool timedOut = false;
    const auto waitStart = std::chrono::steady_clock::now();
    struct Trace {
        const void* caller; const bool& timedOut; std::chrono::steady_clock::time_point start;
        ~Trace() { KernelTraceWait_nid_postfix("cond", caller, static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start).count()), timedOut); }
    } trace{caller, timedOut, waitStart};
    if (m->_type == MutexType::Recursive) {
        std::unique_lock<std::recursive_timed_mutex> lock(m->_rmtx, std::adopt_lock);
        const auto previousCount = m->_count;
        m->_count = 0;
        m->_ownerCaller.store(0, std::memory_order_release);
        m->_ownerNativeTid.store(0, std::memory_order_release);
        m->_ownerSinceMs.store(0, std::memory_order_release);
        m->_owner.store(std::thread::id{}, std::memory_order_release);
        if (deadlineNanos) timedOut = !c->_cv.WaitUntil(lock, *deadlineNanos);
        else c->_cv.Wait(lock);
        m->_ownerCaller.store(reinterpret_cast<std::uintptr_t>(caller), std::memory_order_release);
        m->_ownerSinceMs.store(static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()), std::memory_order_release);
#ifdef _WIN32
        m->_ownerNativeTid.store(static_cast<std::uint32_t>(GetCurrentThreadId()), std::memory_order_release);
#endif
        m->_owner.store(std::this_thread::get_id(), std::memory_order_release);
        m->_count = previousCount;
        lock.release();
        return timedOut ? sceTimedOut : 0;
    }
    std::unique_lock<std::timed_mutex> lock(m->_mtx, std::adopt_lock);
    m->_ownerCaller.store(0, std::memory_order_release);
        m->_ownerNativeTid.store(0, std::memory_order_release);
        m->_ownerSinceMs.store(0, std::memory_order_release);
    m->_owner.store(std::thread::id{}, std::memory_order_release);
    if (deadlineNanos) timedOut = !c->_cv.WaitUntil(lock, *deadlineNanos);
    else c->_cv.Wait(lock);
    m->_ownerCaller.store(reinterpret_cast<std::uintptr_t>(caller), std::memory_order_release);
        m->_ownerSinceMs.store(static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()), std::memory_order_release);
#ifdef _WIN32
        m->_ownerNativeTid.store(static_cast<std::uint32_t>(GetCurrentThreadId()), std::memory_order_release);
#endif
    m->_owner.store(std::this_thread::get_id(), std::memory_order_release);
    lock.release();
    return timedOut ? sceTimedOut : 0;
}

}

int CondOperations::AbsoluteTimedwait(PthreadCond* cond, PthreadMutex* mutex, const KernelTimespec* abstime) {
    KernelUseconds usec = 0;
    if (!PosixThread::RelativeMicroseconds(resolveCond(cond)->_clockid, abstime, &usec))
        throw std::invalid_argument("Invalid absolute condition variable timeout");
    return waitUntil(cond, mutex, TimedWait::DeadlineNanos(usec), __builtin_return_address(0));
}

extern "C" {

int APS5_VABI scePthreadCondattrInit(PthreadCondattr* attr) {
    if (!attr)
        throw std::invalid_argument("Condition attribute pointer is null");
    *attr = new PthreadCondattrPrivate{0};
    return 0;
}

int APS5_VABI scePthreadCondattrDestroy(PthreadCondattr* attr) {
    if (!attr || !*attr)
        throw std::invalid_argument("Condition attributes are not initialized");
    delete *attr;
    *attr = nullptr;
    return 0;
}

int APS5_VABI scePthreadCondattrSetclock(PthreadCondattr* attr, KernelClockid clockId) {
    if (!attr || !*attr)
        throw std::invalid_argument("Condition attributes are not initialized");
    (*attr)->_clockid = static_cast<int>(clockId);
    return 0;
}

int APS5_VABI scePthreadCondInit(PthreadCond* cond, const PthreadCondattr* attr, const char*) {
    if (!cond)
        throw std::invalid_argument("Condition variable pointer is null");
    if (attr && !*attr)
        throw std::invalid_argument("Condition attributes are not initialized");
    auto replacement = std::make_unique<PthreadCondPrivate>();
    if (attr)
        replacement->_clockid = (*attr)->_clockid;
    std::lock_guard lock(condInitializationMutex);
    std::atomic_ref<PthreadCond>(*cond).store(replacement.release(), std::memory_order_release);
    return 0;
}

int APS5_VABI scePthreadCondDestroy(PthreadCond* cond) {
    if (!cond)
        throw std::invalid_argument("Condition variable pointer is null");
    std::lock_guard lock(condInitializationMutex);
    if (*cond == destroyedCond())
        throw std::runtime_error("Condition variable has already been destroyed");
    delete *cond;
    std::atomic_ref<PthreadCond>(*cond).store(destroyedCond(), std::memory_order_release);
    return 0;
}

int APS5_VABI scePthreadCondSignal(PthreadCond* cond) {
    auto* resolved = resolveCond(cond);
    if (tracePendingConds()) {
        static std::atomic<unsigned> reports{0};
        const unsigned count = reports.fetch_add(1, std::memory_order_relaxed);
        if (count < 64 || count % 512 == 0) {
#ifdef _WIN32
            const auto tid = static_cast<unsigned>(GetCurrentThreadId());
#else
            const auto tid = 0u;
#endif
            std::fprintf(stderr, "[cond.notify] signal tid=%u cond=%p\n", tid, static_cast<void*>(resolved));
            std::fflush(stderr);
        }
    }
    resolved->_cv.NotifyOne();
    return 0;
}

int APS5_VABI scePthreadCondBroadcast(PthreadCond* cond) {
    auto* resolved = resolveCond(cond);
    if (tracePendingConds()) {
        static std::atomic<unsigned> reports{0};
        const unsigned count = reports.fetch_add(1, std::memory_order_relaxed);
        if (count < 64 || count % 512 == 0) {
#ifdef _WIN32
            const auto tid = static_cast<unsigned>(GetCurrentThreadId());
#else
            const auto tid = 0u;
#endif
            std::fprintf(stderr, "[cond.notify] broadcast tid=%u cond=%p\n", tid, static_cast<void*>(resolved));
            std::fflush(stderr);
        }
    }
    resolved->_cv.NotifyAll();
    return 0;
}

int APS5_VABI scePthreadCondSignalto(PthreadCond* cond, Pthread thread) {
    (void)thread;
    resolveCond(cond)->_cv.NotifyAll();
    return 0;
}

int APS5_VABI scePthreadCondWait(PthreadCond* cond, PthreadMutex* mutex) {
    return waitUntil(cond, mutex, std::nullopt, __builtin_return_address(0));
}

int APS5_VABI scePthreadCondTimedwait(PthreadCond* cond, PthreadMutex* mutex, KernelUseconds usec) {
    return waitUntil(cond, mutex, TimedWait::DeadlineNanos(usec), __builtin_return_address(0));
}

}
