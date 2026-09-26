package com.ghostlock.app.shizuku;

import com.ghostlock.app.shizuku.IGhostlockCallback;

interface IGhostlockUserService {
    void destroy() = 16777114;
    void runExploit(int primaryCpu, int consumerCpu, boolean safeMode, in byte[] profileBlob, @nullable String debugDir, IGhostlockCallback callback) = 1;

    /**
     * W1 only: the exploit binary with GHOSTLOCK_W1_ONLY=1 *and* GHOSTLOCK_PARK_AFTER_W1=1,
     * which is exactly what tools/device/w1.sh does. The park flag is not optional -- a process
     * that exits right after W1 leaves the forged PI state for the kernel's exit path to walk.
     */
    void runW1Only(in byte[] profileBlob, @nullable String debugDir, IGhostlockCallback callback) = 2;

    /**
     * Run one shell command as the shell user (uid 2000). Used by the root chain for the steps
     * that must not run as the app: `am hang --allow-restart`, launching the root service,
     * and verifying device state between steps.
     */
    void execShell(String command, IGhostlockCallback callback) = 3;
}
