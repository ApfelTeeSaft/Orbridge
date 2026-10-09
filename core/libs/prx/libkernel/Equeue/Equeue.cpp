#include "Equeue.hpp"
#include "prx/libkernel/Time/include/Time.hpp"
#include "prx/libkernel/Socket/include/SocketPoll.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <atomic>
#ifdef _WIN32
#include <windows.h>
#endif
#include <limits>
#include <mutex>
#include <stdexcept>
#include <unordered_map>

static std::unordered_map<KernelEqueue, KernelEqueueRef> g_equeues;
static std::mutex g_equeueMutex;
static uint64_t g_nextEqueue = 1;

extern "C" {

KernelEqueuePrivate::KernelEqueuePrivate(KernelEqueue handle) : m_handle(handle) {}

KernelEqueuePrivate::~KernelEqueuePrivate() {
    Close();
}

uint64_t KernelEqueuePrivate::MonotonicNs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count()
    );
}

static bool EqueueTraceEnabled() {
    static const bool enabled = [] {
        const char* setting = std::getenv("APS5_TRACE_EQUEUE");
        return setting && setting[0] && !(setting[0] == '0' && setting[1] == 0);
    }();
    return enabled;
}

static unsigned long EqueueTraceTid() {
#ifdef _WIN32
    return static_cast<unsigned long>(GetCurrentThreadId());
#else
    return 0;
#endif
}

void KernelEqueuePrivate::TraceState(const char* phase, uint64_t elapsedNs) const {
    if (!EqueueTraceEnabled()) return;
    std::fprintf(stderr,
        "[equeue.trace] %s tid=%lu eq=%llu name='%s' elapsed_ms=%llu watched=%zu closed=%d\n",
        phase, EqueueTraceTid(), static_cast<unsigned long long>(m_handle),
        m_name.c_str(), static_cast<unsigned long long>(elapsedNs / 1000000ULL),
        m_events.size(), m_closed ? 1 : 0);
    unsigned count = 0;
    for (const auto& entry : m_events) {
        if (++count > 16) {
            std::fprintf(stderr, "[equeue.trace]   ... additional watchers omitted\n");
            break;
        }
        std::fprintf(stderr,
            "[equeue.trace]   ident=%llu filter=%d flags=0x%x triggered=%d queued=%zu deadline=%llu\n",
            static_cast<unsigned long long>(entry.event.ident),
            static_cast<int>(entry.event.filter), static_cast<unsigned>(entry.event.flags),
            entry.triggered ? 1 : 0, entry.pendingEvents.size(),
            static_cast<unsigned long long>(entry.deadlineNs));
    }
    std::fflush(stderr);
}

void KernelEqueuePrivate::Close() {
    std::unique_lock lock(m_mutex);
    if (m_closed) {
        return;
    }
    m_closed = true;
    for (auto& ev : m_events) {
        if (ev.filter.deleteEventFunc != nullptr) {
            auto owner = ev.filter.owner;
            ev.filter.deleteEventFunc(m_handle, &ev);
        }
    }
    m_events.clear();
    m_cond.NotifyAll();
}

void KernelEqueuePrivate::TriggerExpiredTimers(uint64_t nowNs) {
    for (auto& ev : m_events) {
        if (ev.deadlineNs != 0 && ev.deadlineNs <= nowNs) {
            if (ev.event.filter == EVFILT_TIMER) {
                const uint64_t count = ev.intervalNs == 0
                    ? (ev.triggered ? 0 : 1)
                    : 1 + (nowNs - ev.deadlineNs) / ev.intervalNs;
                ev.event.data += static_cast<intptr_t>(count);
                ev.deadlineNs += count * ev.intervalNs;
            }
            ev.triggered = true;
        }
    }
}

// Poll the libSceNet descriptor provider without blocking. Guest socket
// identifiers are not CRT file descriptors or native Windows SOCKET handles.
bool KernelEqueuePrivate::HasSocketEvents() const {
    return std::any_of(m_events.begin(), m_events.end(), [](const auto& event) {
        return event.event.filter == EVFILT_READ || event.event.filter == EVFILT_WRITE;
    });
}

void KernelEqueuePrivate::RefreshSocketEvents() {
    const auto poller = KernelGetSocketPoller_nid_no_patch();
    for (auto& event : m_events) {
        const auto filter = event.event.filter;
        if (filter != EVFILT_READ && filter != EVFILT_WRITE) continue;
        if (!poller) {
            event.triggered = true;
            event.event.flags |= EV_ERROR;
            event.event.data = SCE_KERNEL_ERROR_EOPNOTSUPP;
            continue;
        }
        const short requested = filter == EVFILT_READ
            ? KernelSocketPoll::Readable : KernelSocketPoll::Writable;
        KernelSocketPoll::Entry entry{static_cast<int>(event.event.ident), requested, 0};
        const int result = poller(&entry, 1, 0);
        if (result < 0 || (entry.revents & KernelSocketPoll::Unknown) != 0) {
            event.triggered = true;
            event.event.flags |= EV_ERROR;
            event.event.data = result < 0 ? SceKernelError(-result) : SCE_KERNEL_ERROR_EBADF;
        } else {
            event.event.flags &= static_cast<uint16_t>(~EV_ERROR);
            event.triggered = (entry.revents & (requested |
                                                KernelSocketPoll::HangUp |
                                                KernelSocketPoll::Error)) != 0;
            // The existing poller reports readiness, not a byte count.
            event.event.data = 0;
        }
    }
}

bool KernelEqueuePrivate::NextTimerWaitMicros(uint64_t nowNs, uint32_t* out) const {
    uint64_t nearest = std::numeric_limits<uint64_t>::max();
    for (const auto& ev : m_events) {
        if (!ev.triggered && ev.deadlineNs != 0) {
            nearest = std::min(nearest, ev.deadlineNs);
        }
    }
    if (nearest == std::numeric_limits<uint64_t>::max()) {
        return false;
    }
    const uint64_t remainingNs = nearest > nowNs ? nearest - nowNs : 0;
    const uint64_t roundedUs = std::max<uint64_t>(1, (remainingNs + 999u) / 1000u);
    *out = static_cast<uint32_t>(std::min<uint64_t>(roundedUs, std::numeric_limits<uint32_t>::max()));
    return true;
}

int KernelEqueuePrivate::GetTriggeredEvents(KernelEvent* ev, int num) {
    std::unique_lock lock(m_mutex);
    if (m_closed) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    TriggerExpiredTimers(MonotonicNs());
    RefreshSocketEvents();
    int ret = 0;
    for (auto it = m_events.begin(); it != m_events.end();) {
        auto& e = *it;
        bool erase = false;
        while (e.triggered) {
            ev[ret++] = e.event;
            if ((e.event.flags & EV_ONESHOT) != 0) {
                erase = true;
                break;
            }
            if (e.filter.resetFunc != nullptr) {
                e.filter.resetFunc(&e);
            } else if ((e.event.flags & EV_CLEAR) != 0) {
                e.triggered = false;
                e.event.fflags = 0;
                e.event.data = 0;
            }
            if (!e.pendingEvents.empty()) {
                e.event = e.pendingEvents.front();
                e.pendingEvents.pop_front();
                e.triggered = true;
            }
            if (ret >= num) {
                break;
            }
        }
        it = erase ? m_events.erase(it) : std::next(it);
        if (ret >= num) {
            break;
        }
    }
    return ret;
}

int KernelEqueuePrivate::WaitForEvents(KernelEvent* ev, int num, uint32_t micros) {
    std::unique_lock lock(m_mutex);
    if (m_closed) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    const std::uint64_t deadline = TimedWait::DeadlineNanos(micros);
    const bool trace = EqueueTraceEnabled();
    const auto traceStart = MonotonicNs();
    std::uint64_t lastTrace = traceStart;
    if (trace) TraceState("wait-enter", 0);
    for (;;) {
        const auto traceNow = MonotonicNs();
        if (trace && traceNow - lastTrace >= 2000000000ULL) {
            TraceState("wait-pending", traceNow - traceStart);
            lastTrace = traceNow;
        }
        TriggerExpiredTimers(MonotonicNs());
        RefreshSocketEvents();
        int ret = 0;
        for (auto it = m_events.begin(); it != m_events.end() && ret < num;) {
            auto& e = *it;
            bool erase = false;
            while (e.triggered) {
                ev[ret++] = e.event;
                if ((e.event.flags & EV_ONESHOT) != 0) {
                    erase = true;
                    break;
                }
                if (e.filter.resetFunc != nullptr) {
                    e.filter.resetFunc(&e);
                } else if ((e.event.flags & EV_CLEAR) != 0) {
                    e.triggered = false;
                    e.event.fflags = 0;
                    e.event.data = 0;
                }
                if (!e.pendingEvents.empty()) {
                    e.event = e.pendingEvents.front();
                    e.pendingEvents.pop_front();
                    e.triggered = true;
                }
                if (ret >= num) {
                    break;
                }
            }
            it = erase ? m_events.erase(it) : std::next(it);
        }
        if (ret != 0) {
            if (trace) TraceState("wait-complete", MonotonicNs() - traceStart);
            return ret;
        }
        if (m_closed) {
            return SCE_KERNEL_ERROR_EBADF;
        }
        // libSceNet's poller is nonblocking, so revisit pending read
        // watchers periodically. Keep the queue lock released while sleeping,
        // allowing concurrent trigger/deletion, and retain timer deadlines.
        uint32_t timerWait = 0;
        const bool hasTimer = NextTimerWaitMicros(MonotonicNs(), &timerWait);
        const std::uint64_t now = TimedWait::NowNanos();
        if (micros != 0 && now >= deadline) return 0;
        const bool hasSocket = HasSocketEvents();
        if (!hasTimer && !hasSocket && micros == 0) {
            // Diagnostics only: periodically wake to report missing events.
            // WaitUntil releases m_mutex while sleeping, just like Wait.
            if (trace) m_cond.WaitUntil(lock, TimedWait::NowNanos() + 2000000000ULL);
            else m_cond.Wait(lock);
            continue;
        }
        std::uint64_t wake = micros == 0 ? std::numeric_limits<std::uint64_t>::max() : deadline;
        if (hasTimer) wake = std::min(wake, now + static_cast<std::uint64_t>(timerWait) * 1000ULL);
        if (hasSocket) wake = std::min(wake, now + 10'000'000ULL); // 10 ms
        m_cond.WaitUntil(lock, wake);
    }
}

int KernelEqueuePrivate::AddEvent(const KernelEqueueEvent& event) {
    std::unique_lock lock(m_mutex);
    if (m_closed) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    auto it = std::find_if(m_events.begin(), m_events.end(),
        [ident = event.event.ident, filter = event.event.filter](const auto& e) {
            return e.event.ident == ident && e.event.filter == filter;
        }
    );
    if (it != m_events.end()) {
        if (event.event.filter == EVFILT_TIMER) {
            TriggerExpiredTimers(MonotonicNs());
        }
        it->deadlineNs = event.deadlineNs;
        it->intervalNs = event.intervalNs;
        it->event.udata = event.event.udata;
        for (auto& pending : it->pendingEvents) {
            pending.udata = event.event.udata;
        }
    } else {
        m_events.push_back(event);
    }
    m_cond.NotifyOne();
    return EQUEUE_OK;
}

int KernelEqueuePrivate::TriggerEvent(uintptr_t ident, int16_t filter, void* triggerData) {
    std::unique_lock lock(m_mutex);
    if (m_closed) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    auto it = std::find_if(m_events.begin(), m_events.end(),
        [ident, filter](const auto& e) {
            return e.event.ident == ident && e.event.filter == filter;
        }
    );
    if (it == m_events.end()) {
        return SCE_KERNEL_ERROR_ENOENT;
    }
    if (it->filter.triggerFunc != nullptr) {
        it->filter.triggerFunc(&*it, triggerData);
    } else {
        it->triggered = true;
    }
    m_cond.NotifyOne();
    return EQUEUE_OK;
}

int KernelEqueuePrivate::DeleteEvent(uintptr_t ident, int16_t filter) {
    std::unique_lock lock(m_mutex);
    if (m_closed) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    auto it = std::find_if(m_events.begin(), m_events.end(),
        [ident, filter](const auto& e) {
            return e.event.ident == ident && e.event.filter == filter;
        }
    );
    if (it == m_events.end()) {
        return SCE_KERNEL_ERROR_ENOENT;
    }
    if (it->filter.deleteEventFunc != nullptr) {
        auto owner = it->filter.owner;
        it->filter.deleteEventFunc(m_handle, &*it);
    }
    m_events.erase(it);
    return EQUEUE_OK;
}

KernelEqueueRef EqueuePin_nid_postfix(KernelEqueue eq) {
    if (eq == 0) {
        return {};
    }
    std::unique_lock lock(g_equeueMutex);
    auto it = g_equeues.find(eq);
    return it != g_equeues.end() ? it->second : KernelEqueueRef{};
}

int APS5_VABI EqueueAddEvent_nid_postfix(KernelEqueue eq, const KernelEqueueEvent& event) {
    auto owner = EqueuePin_nid_postfix(eq);
    if (!owner) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    return owner->AddEvent(event);
}

int APS5_VABI EqueueTriggerEvent_nid_postfix(KernelEqueue eq, uintptr_t ident, int16_t filter, void* triggerData) {
    auto owner = EqueuePin_nid_postfix(eq);
    if (!owner) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    return owner->TriggerEvent(ident, filter, triggerData);
}

int APS5_VABI EqueueDeleteEvent_nid_postfix(KernelEqueue eq, uintptr_t ident, int16_t filter) {
    auto owner = EqueuePin_nid_postfix(eq);
    if (!owner) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    return owner->DeleteEvent(ident, filter);
}


int APS5_VABI sceKernelCreateEqueue(KernelEqueue* eq, const char* name) {
    if (eq == nullptr || name == nullptr) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    std::unique_lock lock(g_equeueMutex);
    if (g_nextEqueue > static_cast<uint64_t>(std::numeric_limits<KernelEqueue>::max())) {
        throw std::runtime_error("equeue handle space exhausted");
    }
    *eq = static_cast<KernelEqueue>(g_nextEqueue++);
    auto owner = std::make_shared<KernelEqueuePrivate>(*eq);
    owner->SetName(std::string(name));
    g_equeues.emplace(*eq, std::move(owner));
    return EQUEUE_OK;
}

int APS5_VABI sceKernelDeleteEqueue(KernelEqueue eq) {
    KernelEqueueRef owner;
    {
        std::unique_lock lock(g_equeueMutex);
        auto it = g_equeues.find(eq);
        if (it == g_equeues.end()) {
            return SCE_KERNEL_ERROR_EBADF;
        }
        owner = std::move(it->second);
        g_equeues.erase(it);
    }
    owner->Close();
    return EQUEUE_OK;
}

int APS5_VABI sceKernelWaitEqueue(KernelEqueue eq, KernelEvent* ev, int num, int* out, const KernelUseconds* timo) {
    auto owner = EqueuePin_nid_postfix(eq);
    if (!owner) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    if (ev == nullptr) {
        return SCE_KERNEL_ERROR_EFAULT;
    }
    if (num < 1 || out == nullptr) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    const auto waitStart = std::chrono::steady_clock::now();
    if (timo == nullptr) {
        *out = owner->WaitForEvents(ev, num, 0);
    } else if (*timo == 0) {
        *out = owner->GetTriggeredEvents(ev, num);
    } else {
        *out = owner->WaitForEvents(ev, num, *timo);
    }
    if (timo == nullptr || *timo != 0) {
        KernelTraceWait_nid_postfix("equeue", __builtin_return_address(0), static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - waitStart).count()), *out == 0);
    }
    if (*out == SCE_KERNEL_ERROR_EBADF) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    if (*out == 0) {
        return SCE_KERNEL_ERROR_ETIMEDOUT;
    }
    return EQUEUE_OK;
}

int APS5_VABI sceKernelAddUserEvent(KernelEqueue eq, int id) {
    KernelEqueueEvent event{};
    event.event.ident = static_cast<uintptr_t>(id);
    event.event.filter = EVFILT_USER;
    event.event.flags = EV_ADD;
    event.filter.triggerFunc = [](KernelEqueueEvent* e, void* data) {
        e->triggered = true;
        e->event.data = reinterpret_cast<intptr_t>(data);
        e->event.udata = data;
    };
    event.filter.resetFunc = [](KernelEqueueEvent* e) {
        if ((e->event.flags & EV_CLEAR) != 0) {
            e->triggered = false;
            e->event.fflags = 0;
            e->event.data = 0;
        }
    };
    return EqueueAddEvent_nid_postfix(eq, event);
}

int APS5_VABI sceKernelAddUserEventEdge(KernelEqueue eq, int id) {
    KernelEqueueEvent event{};
    event.event.ident = static_cast<uintptr_t>(id);
    event.event.filter = EVFILT_USER;
    event.event.flags = EV_ADD | EV_CLEAR;
    event.filter.triggerFunc = [](KernelEqueueEvent* e, void* data) {
        e->triggered = true;
        e->event.data = reinterpret_cast<intptr_t>(data);
        e->event.udata = data;
    };
    event.filter.resetFunc = [](KernelEqueueEvent* e) {
        if ((e->event.flags & EV_CLEAR) != 0) {
            e->triggered = false;
            e->event.fflags = 0;
            e->event.data = 0;
        }
    };
    return EqueueAddEvent_nid_postfix(eq, event);
}

int APS5_VABI sceKernelTriggerUserEvent(KernelEqueue eq, int id, void* udata) {
    return EqueueTriggerEvent_nid_postfix(eq, static_cast<uintptr_t>(id), EVFILT_USER, udata);
}

int APS5_VABI sceKernelDeleteUserEvent(KernelEqueue eq, int id) {
    return EqueueDeleteEvent_nid_postfix(eq, static_cast<uintptr_t>(id), EVFILT_USER);
}

int APS5_VABI sceKernelAddReadEvent(KernelEqueue eq, int fd, std::size_t lowWater, void* userData) {
    if (!EqueuePin_nid_postfix(eq)) return SCE_KERNEL_ERROR_EBADF;
    if (fd < 0) return SCE_KERNEL_ERROR_EBADF;
    // The current poller reports a readiness bit, not the byte count
    // required to honor low-water thresholds greater than one.
    if (lowWater > 1) return SCE_KERNEL_ERROR_EOPNOTSUPP;
    const auto poller = KernelGetSocketPoller_nid_no_patch();
    if (!poller) return SCE_KERNEL_ERROR_EOPNOTSUPP;

    // Probe the descriptor against the existing libSceNet table rather than
    // accepting unknown host/guest descriptors and silently never firing.
    KernelSocketPoll::Entry probe{fd, KernelSocketPoll::Readable, 0};
    const int status = poller(&probe, 1, 0);
    if (status < 0) return SceKernelError(-status);
    if ((probe.revents & KernelSocketPoll::Unknown) != 0) return SCE_KERNEL_ERROR_EBADF;

    KernelEqueueEvent event{};
    event.event.ident = static_cast<uintptr_t>(fd);
    event.event.filter = EVFILT_READ;
    event.event.flags = EV_ADD | EV_CLEAR;
    event.event.udata = userData;
    return EqueueAddEvent_nid_postfix(eq, event);
}

int APS5_VABI sceKernelDeleteReadEvent(KernelEqueue eq, int fd) {
    // The read and write filters are separate registrations on the same
    // descriptor. Only remove EVFILT_READ, preserving other queue entries.
    return EqueueDeleteEvent_nid_postfix(eq, static_cast<uintptr_t>(fd), EVFILT_READ);
}

int APS5_VABI sceKernelAddWriteEvent(KernelEqueue eq, int fd, std::size_t lowWater, void* userData) {
    if (!EqueuePin_nid_postfix(eq)) return SCE_KERNEL_ERROR_EBADF;
    if (fd < 0) return SCE_KERNEL_ERROR_EBADF;
    if (lowWater > 1) return SCE_KERNEL_ERROR_EOPNOTSUPP;
    const auto poller = KernelGetSocketPoller_nid_no_patch();
    if (!poller) return SCE_KERNEL_ERROR_EOPNOTSUPP;

    KernelSocketPoll::Entry probe{fd, KernelSocketPoll::Writable, 0};
    const int status = poller(&probe, 1, 0);
    if (status < 0) return SceKernelError(-status);
    if ((probe.revents & KernelSocketPoll::Unknown) != 0) return SCE_KERNEL_ERROR_EBADF;

    KernelEqueueEvent event{};
    event.event.ident = static_cast<uintptr_t>(fd);
    event.event.filter = EVFILT_WRITE;
    event.event.flags = EV_ADD | EV_CLEAR;
    event.event.udata = userData;
    return EqueueAddEvent_nid_postfix(eq, event);
}

int APS5_VABI sceKernelDeleteWriteEvent(KernelEqueue eq, int fd) {
    // Delete only the descriptor's write registration, not a READ or USER
    // event with the same identifier. The queue helper checks handle
    // validity and whether the registration exists.
    return EqueueDeleteEvent_nid_postfix(eq, static_cast<uintptr_t>(fd), EVFILT_WRITE);
}

int APS5_VABI sceKernelAddHRTimerEvent(KernelEqueue eq, int id, const KernelTimespec* ts, void* udata) {
    if (ts == nullptr) {
        return SCE_KERNEL_ERROR_EFAULT;
    }
    if (ts->tv_sec < 0 || ts->tv_nsec < 0 || ts->tv_nsec >= 1000000000LL) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    const uint64_t delayNs =
        static_cast<uint64_t>(ts->tv_sec) * 1000000000ULL +
        static_cast<uint64_t>(ts->tv_nsec);
    const uint64_t nowNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count()
    );
    KernelEqueueEvent event{};
    event.deadlineNs = (delayNs <= std::numeric_limits<uint64_t>::max() - nowNs)
        ? nowNs + delayNs : std::numeric_limits<uint64_t>::max();
    event.event.ident = static_cast<uintptr_t>(id);
    event.event.filter = EVFILT_HRTIMER;
    event.event.flags = EV_ADD | EV_ONESHOT;
    event.event.udata = udata;
    return EqueueAddEvent_nid_postfix(eq, event);
}

int APS5_VABI sceKernelDeleteHRTimerEvent(KernelEqueue eq, int id) {
    return EqueueDeleteEvent_nid_postfix(eq, static_cast<uintptr_t>(id), EVFILT_HRTIMER);
}

int APS5_VABI sceKernelAddTimerEvent(KernelEqueue eq, int id, KernelUseconds usec, void* udata) {
    const uint64_t intervalNs = static_cast<uint64_t>(usec) * 1000ULL;
    KernelEqueueEvent event{};
    event.deadlineNs = KernelEqueuePrivate::MonotonicNs() + intervalNs;
    event.intervalNs = intervalNs;
    event.event.ident = static_cast<uintptr_t>(id);
    event.event.filter = EVFILT_TIMER;
    event.event.flags = EV_ADD | EV_CLEAR;
    event.event.udata = udata;
    return EqueueAddEvent_nid_postfix(eq, event);
}

int APS5_VABI sceKernelDeleteTimerEvent(KernelEqueue eq, int id) {
    return EqueueDeleteEvent_nid_postfix(eq, static_cast<uintptr_t>(id), EVFILT_TIMER);
}

int APS5_VABI sceKernelAddAmprEvent(KernelEqueue eq, int id, void* udata) {
    if (eq == 0) {
        return EQUEUE_OK;
    }
    KernelEqueueEvent event{};
    event.event.ident = static_cast<uintptr_t>(id);
    event.event.filter = EVFILT_AMPR;
    event.event.flags = EV_ADD | EV_CLEAR;
    event.event.udata = udata;
    event.filter.triggerFunc = [](KernelEqueueEvent* e, void* data) {
        KernelEvent triggered = e->event;
        triggered.data = static_cast<intptr_t>(reinterpret_cast<uintptr_t>(data));
        if (e->triggered) {
            e->pendingEvents.push_back(triggered);
        } else {
            e->event = triggered;
            e->triggered = true;
        }
    };
    event.filter.resetFunc = [](KernelEqueueEvent* e) {
        if ((e->event.flags & EV_CLEAR) != 0) {
            e->triggered = false;
            e->event.fflags = 0;
            e->event.data = 0;
        }
    };
    EqueueAddEvent_nid_postfix(eq, event);
    return EQUEUE_OK;
}

int APS5_VABI sceKernelAddAmprSystemEvent(KernelEqueue eq, int id, void* udata) {
    return sceKernelAddAmprEvent(eq, id, udata);
}

int APS5_VABI sceKernelDeleteAmprEvent(KernelEqueue eq, int id) {
    if (eq == 0) {
        return EQUEUE_OK;
    }
    EqueueDeleteEvent_nid_postfix(eq, static_cast<uintptr_t>(id), EVFILT_AMPR);
    return EQUEUE_OK;
}

int APS5_VABI sceKernelDeleteAmprSystemEvent(KernelEqueue eq, int id) {
    return sceKernelDeleteAmprEvent(eq, id);
}

}
