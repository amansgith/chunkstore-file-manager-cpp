#include <condition_variable>
#include <atomic>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>
#include <future>

class ThreadPool {
public:
    explicit ThreadPool(size_t thread_count);
    ~ThreadPool();

    template<typename F, typename... Args>
    auto enqueue(F&& f, Args&&... args) -> std::future<typename std::invoke_result_t<F, Args...>> {
        using return_type = typename std::invoke_result_t<F, Args...>;

        auto task = std::make_shared<std::packaged_task<return_type()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...)
        );

        std::future<return_type> res = task->get_future();
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            tasks.push([task]() { (*task)(); });
            ++active_tasks;
        }
        condition.notify_one();
        return res;
    }

    void wait_for_tasks();

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;

    std::mutex queue_mutex;
    std::condition_variable condition;
    std::atomic<bool> stop;

    std::atomic<size_t> active_tasks = 0;
    std::condition_variable tasks_done;

    void worker_thread();
};