package pl.lebihan.authnkey

import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.os.CancellationSignal
import android.util.Log

class AuthnkeyAutofillService : AutofillService() {

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        // Authnkey 主要使用 Credential Manager (Passkeys)。
        // 这里的 Autofill 实现是为了兼容系统设置的“首选服务”列表。
        // 如果需要，你可以在这里返回 null 或者一个空的 FillResponse。
        
        Log.d("AuthnkeyAutofill", "onFillRequest called - bridging to Credential Manager if needed")
        
        // 返回 null 表示不提供传统的表单自动填充，或者你可以根据需求实现它
        callback.onSuccess(null)
    }

    override fun onSaveRequest(
        request: SaveRequest,
        callback: SaveCallback
    ) {
        // 不需要处理传统的保存请求
        callback.onSuccess()
    }
}
