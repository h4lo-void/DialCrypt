package io.github.h4lovoid.dialcrypt.ui.components

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import android.util.Size
import android.view.View
import androidx.activity.compose.LocalActivityResultRegistryOwner
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.AspectRatioStrategy
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.app.ActivityCompat
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PhotoCamera
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.ui.theme.Radius
import io.github.h4lovoid.dialcrypt.ui.theme.Space
import io.github.h4lovoid.dialcrypt.ui.theme.Tone
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.floor
import kotlin.math.max

/**
 * Camera preview that looks for a QR code and hands its text to [onText] on the main thread.
 * [onText] returns true when the text was used, which stops scanning, or false to keep scanning
 * (for example, a QR code from another app); the same rejected text is not reported twice in a row.
 * Only the part of each frame that the square viewfinder shows (a little inside its edges) is
 * decoded, so a code that is not on screen is never read.
 * Frames are decoded in memory only: the brightness copy of each frame is wiped right after it is
 * read and nothing is stored or logged. The camera is released when this leaves the composition.
 * Asks for the camera permission first; without it, the reason is shown instead of the preview.
 * When the system will not ask again (the permission was refused for good), the button opens this app's
 * settings page instead, and the preview starts as soon as the app is back in front with the permission granted.
 */
@Composable
fun QrScanner(onText: (String) -> Boolean, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    fun granted(): Boolean =
        ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED

    var allowed by remember { mutableStateOf(granted()) }
    var denied by remember { mutableStateOf(false) }
    // True once the system has stopped showing its permission prompt, so asking again does nothing.
    var blocked by remember { mutableStateOf(false) }
    // SecureActivity is a ComponentActivity; without a result registry (previews) only the reason is shown.
    val request = if (LocalActivityResultRegistryOwner.current != null) {
        rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { ok ->
            allowed = ok
            denied = !ok
            val activity = context.findActivity()
            blocked = !ok && activity != null &&
                !ActivityCompat.shouldShowRequestPermissionRationale(activity, Manifest.permission.CAMERA)
        }
    } else {
        null
    }
    LaunchedEffect(Unit) {
        if (!allowed) request?.launch(Manifest.permission.CAMERA)
    }
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME && granted()) allowed = true
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    if (allowed) {
        CameraPreview(onText, modifier)
    } else {
        Column(modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(Space.sm)) {
            InlineMessage(stringResource(R.string.add_camera_needed), if (denied) Tone.DANGER else Tone.WARN)
            if (request != null) {
                SecondaryButton(
                    stringResource(if (blocked) R.string.add_camera_settings else R.string.add_camera_allow),
                    onClick = {
                        when {
                            granted() -> allowed = true
                            blocked -> openAppSettings(context)
                            else -> request.launch(Manifest.permission.CAMERA)
                        }
                    },
                    icon = Icons.Filled.PhotoCamera,
                )
            }
        }
    }
}

private fun Context.findActivity(): Activity? {
    var c: Context? = this
    while (c is ContextWrapper) {
        if (c is Activity) return c
        c = c.baseContext
    }
    return null
}

/** Opens the system settings page of this app, where the camera permission can be turned on. */
private fun openAppSettings(context: Context) {
    val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null))
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    runCatching { context.startActivity(intent) }
}

@Composable
private fun CameraPreview(onText: (String) -> Boolean, modifier: Modifier) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val latest by rememberUpdatedState(onText)
    var failed by remember { mutableStateOf(false) }
    val previewView = remember {
        PreviewView(context).apply {
            // TextureView draws inside the app window, so the window's FLAG_SECURE also covers the preview.
            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
            scaleType = PreviewView.ScaleType.FILL_CENTER
        }
    }

    DisposableEffect(lifecycleOwner) {
        val main = ContextCompat.getMainExecutor(context)
        val worker = Executors.newSingleThreadExecutor()
        val stopped = AtomicBoolean(false)
        var disposed = false
        var bound: ProcessCameraProvider? = null
        var lastRejected: String? = null
        // Size of the viewfinder, read by the analysis thread: width in the high 32 bits, height in the low.
        val viewSize = AtomicLong(0)
        fun keepSize(v: View) = viewSize.set((v.width.toLong() shl 32) or v.height.toLong())
        val onLayout = View.OnLayoutChangeListener { v, _, _, _, _, _, _, _, _ -> keepSize(v) }
        previewView.addOnLayoutChangeListener(onLayout)
        keepSize(previewView)

        // Preview and analysis ask for the same aspect ratio, so a frame covers what the preview covers.
        val sameShape = AspectRatioStrategy.RATIO_16_9_FALLBACK_AUTO_STRATEGY
        val preview = Preview.Builder()
            .setResolutionSelector(ResolutionSelector.Builder().setAspectRatioStrategy(sameShape).build())
            .build()
            .also { it.setSurfaceProvider(previewView.surfaceProvider) }
        val analysis = ImageAnalysis.Builder()
            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
            .setResolutionSelector(
                ResolutionSelector.Builder()
                    .setAspectRatioStrategy(sameShape)
                    .setResolutionStrategy(
                        ResolutionStrategy(Size(1280, 720), ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER),
                    )
                    .build(),
            )
            .build()
        val decoder = QrFrameDecoder()
        analysis.setAnalyzer(worker) { image ->
            val size = viewSize.get()
            val text = try {
                if (stopped.get()) null else decoder.decode(image, (size ushr 32).toInt(), size.toInt())
            } finally {
                image.close()
            }
            if (text != null) {
                main.execute {
                    if (stopped.get() || text == lastRejected) return@execute
                    if (latest(text)) {
                        stopped.set(true)
                        analysis.clearAnalyzer()
                    } else {
                        lastRejected = text
                    }
                }
            }
        }

        val future = ProcessCameraProvider.getInstance(context)
        future.addListener({
            if (disposed) return@addListener
            val provider = runCatching { future.get() }.getOrNull()
            val selector = when {
                provider == null -> null
                runCatching { provider.hasCamera(CameraSelector.DEFAULT_BACK_CAMERA) }.getOrDefault(false) ->
                    CameraSelector.DEFAULT_BACK_CAMERA
                runCatching { provider.hasCamera(CameraSelector.DEFAULT_FRONT_CAMERA) }.getOrDefault(false) ->
                    CameraSelector.DEFAULT_FRONT_CAMERA
                else -> null
            }
            val ok = provider != null && selector != null &&
                runCatching { provider.bindToLifecycle(lifecycleOwner, selector, preview, analysis) }.isSuccess
            if (ok) bound = provider else failed = true
        }, main)

        onDispose {
            disposed = true
            stopped.set(true)
            previewView.removeOnLayoutChangeListener(onLayout)
            analysis.clearAnalyzer()
            bound?.unbind(preview, analysis)
            worker.shutdown()
        }
    }

    if (failed) {
        InlineMessage(stringResource(R.string.add_camera_unavailable), Tone.DANGER, modifier.fillMaxWidth())
    } else {
        Box(
            modifier
                .fillMaxWidth()
                .aspectRatio(1f)
                .clip(RoundedCornerShape(Radius.md))
                .background(Color.Black),
        ) {
            AndroidView(factory = { previewView }, modifier = Modifier.fillMaxSize())
        }
    }
}

/** Part of a camera frame, in the frame's own (unrotated) pixels. */
internal data class FrameCrop(val left: Int, val top: Int, val width: Int, val height: Int)

/** Share of each side of the viewfinder left out (half on each edge), so a code cut by the edge is not read. */
internal const val VIEWFINDER_INSET = 0.1

/**
 * The part of an [imageWidth] x [imageHeight] frame that a FILL_CENTER preview of [viewWidth] x [viewHeight]
 * shows, shrunk by [inset] of each side. [rotationDegrees] turns the frame upright, as the preview draws
 * it: FILL_CENTER scales the upright frame to cover the view and cuts the overflow evenly on both sides,
 * so the visible part is centered and only its width and height swap for a sideways sensor.
 * Null for an empty frame or view or a rotation that is not a multiple of 90 degrees.
 */
internal fun visibleCrop(
    imageWidth: Int,
    imageHeight: Int,
    rotationDegrees: Int,
    viewWidth: Int,
    viewHeight: Int,
    inset: Double = VIEWFINDER_INSET,
): FrameCrop? {
    if (imageWidth <= 0 || imageHeight <= 0 || viewWidth <= 0 || viewHeight <= 0) return null
    val turn = ((rotationDegrees % 360) + 360) % 360
    if (turn % 90 != 0) return null
    val sideways = turn == 90 || turn == 270
    val uprightWidth = if (sideways) imageHeight else imageWidth
    val uprightHeight = if (sideways) imageWidth else imageHeight
    val scale = max(viewWidth.toDouble() / uprightWidth, viewHeight.toDouble() / uprightHeight)
    val shownWidth = viewWidth / scale
    val shownHeight = viewHeight / scale
    val keep = 1.0 - inset.coerceIn(0.0, 0.9)
    val width = floor((if (sideways) shownHeight else shownWidth) * keep + 1e-9).toInt().coerceIn(1, imageWidth)
    val height = floor((if (sideways) shownWidth else shownHeight) * keep + 1e-9).toInt().coerceIn(1, imageHeight)
    return FrameCrop((imageWidth - width) / 2, (imageHeight - height) / 2, width, height)
}

/** Reads a QR code from the brightness (Y) plane of one camera frame. Used on the analysis thread only. */
private class QrFrameDecoder {
    private val reader = QRCodeReader()
    private val hints = mapOf(DecodeHintType.TRY_HARDER to true)
    private var luma = ByteArray(0)

    /** Decodes only what the [viewWidth] x [viewHeight] viewfinder shows of [image]. */
    fun decode(image: ImageProxy, viewWidth: Int, viewHeight: Int): String? {
        val plane = image.planes.firstOrNull() ?: return null
        val crop = visibleCrop(image.width, image.height, image.imageInfo.rotationDegrees, viewWidth, viewHeight) ?: return null
        val width = crop.width
        val height = crop.height
        val rowStride = plane.rowStride
        val src = plane.buffer.duplicate()
        if (plane.pixelStride != 1) return null
        if (src.capacity() < (crop.top + height - 1) * rowStride + crop.left + width) return null
        val size = width * height
        if (luma.size < size) luma = ByteArray(size)
        return try {
            for (row in 0 until height) {
                src.position((crop.top + row) * rowStride + crop.left)
                src.get(luma, row * width, width)
            }
            val source = PlanarYUVLuminanceSource(luma, width, height, 0, 0, width, height, false)
            // Local thresholds suit most frames; a large close-up code with big flat modules can defeat them,
            // and one global threshold reads that case.
            read(BinaryBitmap(HybridBinarizer(source))) ?: read(BinaryBitmap(GlobalHistogramBinarizer(source)))
        } catch (e: RuntimeException) {
            // A frame whose buffer does not match its size is skipped; the analysis thread must not crash.
            null
        } finally {
            luma.fill(0, 0, size)
        }
    }

    private fun read(bitmap: BinaryBitmap): String? = try {
        reader.decode(bitmap, hints).text
    } catch (e: Exception) {
        // NotFound, Checksum and Format errors just mean no readable code in this frame.
        null
    } finally {
        reader.reset()
    }
}
