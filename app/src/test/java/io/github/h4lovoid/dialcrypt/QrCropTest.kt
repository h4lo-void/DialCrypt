package io.github.h4lovoid.dialcrypt

import io.github.h4lovoid.dialcrypt.ui.components.FrameCrop
import io.github.h4lovoid.dialcrypt.ui.components.visibleCrop
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Only the part of a camera frame that the viewfinder shows is decoded: check that part for each sensor turn. */
class QrCropTest {
    @Test
    fun aSquareViewfinderShowsTheCenterSquareOfTheFrameForEveryRotation() {
        // A 16:9 frame in a square FILL_CENTER view shows a 720 x 720 square in the middle, however the sensor is turned.
        for (rotation in listOf(0, 90, 180, 270)) {
            assertEquals("rotation $rotation", FrameCrop(280, 0, 720, 720), visibleCrop(1280, 720, rotation, 900, 900, inset = 0.0))
        }
    }

    @Test
    fun theInsetLeavesOutTheEdgesEvenly() {
        // 10% of 720 is 72: 36 pixels off each edge.
        for (rotation in listOf(0, 90, 180, 270)) {
            assertEquals("rotation $rotation", FrameCrop(316, 36, 648, 648), visibleCrop(1280, 720, rotation, 900, 900))
        }
    }

    @Test
    fun aTallViewfinderOnASidewaysSensorKeepsTheFullFrameHeight() {
        // Upright the frame is 720 x 1280; a 300 x 400 view scaled to cover it shows 720 x 960 of it,
        // which in the unrotated frame is 960 wide and 720 high.
        for (rotation in listOf(90, 270)) {
            assertEquals("rotation $rotation", FrameCrop(160, 0, 960, 720), visibleCrop(1280, 720, rotation, 300, 400, inset = 0.0))
        }
    }

    @Test
    fun aTallViewfinderOnAnUprightSensorCutsTheSides() {
        // Upright the frame is 1280 x 720; a 300 x 400 view shows 540 x 720 of it.
        for (rotation in listOf(0, 180)) {
            assertEquals("rotation $rotation", FrameCrop(370, 0, 540, 720), visibleCrop(1280, 720, rotation, 300, 400, inset = 0.0))
        }
    }

    @Test
    fun aWideViewfinderOnA4By3FrameCutsTopAndBottom() {
        // 640 x 480 frame, 400 x 200 view: upright (0 degrees) it shows 640 x 320; turned, upright is 480 x 640
        // and it shows 480 x 240, which is 240 wide and 480 high in the frame.
        assertEquals(FrameCrop(0, 80, 640, 320), visibleCrop(640, 480, 0, 400, 200, inset = 0.0))
        assertEquals(FrameCrop(200, 0, 240, 480), visibleCrop(640, 480, 90, 400, 200, inset = 0.0))
        assertEquals(FrameCrop(200, 0, 240, 480), visibleCrop(640, 480, -270, 400, 200, inset = 0.0))
    }

    @Test
    fun anEmptyFrameOrViewOrAnOddRotationGivesNoCrop() {
        assertNull("view not laid out yet", visibleCrop(1280, 720, 90, 0, 0))
        assertNull(visibleCrop(0, 720, 90, 300, 300))
        assertNull(visibleCrop(1280, 720, 45, 300, 300))
    }
}
