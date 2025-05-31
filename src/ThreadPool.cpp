#include "ThreadPool.h"
#include <iostream>

ThreadPool::ThreadPool(size_t thread_count) : stop(false) {
    for (size_t i = 0; i < thread_count; ++i) {
        workers.emplace_back(&ThreadPool::worker_thread, this);
    }
}

ThreadPool::~ThreadPool() {
    stop = true;
    condition.notify_all();
    for (std::thread &worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

void ThreadPool::worker_thread() {
    while (!stop) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            condition.wait(lock, [this]() { return stop || !tasks.empty(); });
            if (stop && tasks.empty()) {
                return;
            }
            task = std::move(tasks.front());
            tasks.pop();
        }

        // auto start_time = std::chrono::high_resolution_clock::now();
        task();
        // auto end_time = std::chrono::high_resolution_clock::now();
        // auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        

        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            --active_tasks;
            if (tasks.empty() && active_tasks == 0) {
                tasks_done.notify_all();
            }
        }
    }
}

void ThreadPool::wait_for_tasks() {
    std::unique_lock<std::mutex> lock(queue_mutex);
    tasks_done.wait(lock, [this]() { return tasks.empty() && active_tasks == 0; });
}