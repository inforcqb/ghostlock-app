package com.ghostlock.app

import android.app.Application
import com.ghostlock.app.chain.ChainStateStore
import com.ghostlock.app.data.AndroidGhostlockRepository
import com.ghostlock.app.domain.repository.GhostlockRepository

/** Application composition root. It is the only place that binds data implementations to domain ports. */
class GhostlockApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        /* Chain progress survives the zygote restart that `am hang --allow-restart`
         * causes, so the restarted app can say where it stopped. */
        ChainStateStore.init(this)
    }

    fun createRepository(): GhostlockRepository = AndroidGhostlockRepository(this)
}
