package io.github.andreypfau.curve25519.constants.tables

import io.github.andreypfau.curve25519.edwards.EdwardsPoint
import io.github.andreypfau.curve25519.models.CompletedPoint
import io.github.andreypfau.curve25519.models.ProjectiveNielsPoint
import io.github.andreypfau.kotlinx.crypto.subtle.constantTimeEquals

class ProjectiveNielsPointLookupTable(
    val data: Array<ProjectiveNielsPoint>
) {
    fun lookup(x: Byte): ProjectiveNielsPoint {
        // Compute xabs = |x|
        val xmask = x.toInt() shr 7
        val xabs = ((x.toInt() + xmask) xor xmask).toByte()

        // Set t = 0 * P = identity
        val t = ProjectiveNielsPoint().identity()
        for (j in 1 until 9) {
            // Copy `points[j-1] == j*P` onto `t` in constant time if `|x| == j`.
            val c = xabs.constantTimeEquals(j.toByte())
            t.conditionalAssign(data[j - 1], c)
        }
        // Now t == |x| * P.

        val negMask = (xmask and 1).toByte().toInt()
        t.conditionalNegate(negMask)
        // Now t == x * P.
        return t
    }

    companion object {
        // Builds [P, 2P, 3P, ..., 8P] for use by the radix-16 windowed scalar mult in
        // `edwardsMulCommon`. Upstream curve25519-kotlin v0.0.8 had a copy-paste bug from the
        // sister NAF table (`ProjectiveNielsPointNafLookupTable.from`), which builds odd
        // multiples [P, 3P, ..., 15P] — wrong for this lookup, since `lookup(x)` indexes
        // sequentially `data[|x|-1]`. Fix: add `ep` (not `2P`) on each iteration.
        fun from(ep: EdwardsPoint): ProjectiveNielsPointLookupTable {
            val ai = Array(8) {
                ProjectiveNielsPoint.from(ep)
            }

            for (i in 0 until 7) {
                val tmp = CompletedPoint()
                val tmp2 = EdwardsPoint()
                tmp.add(ep, ai[i])
                tmp2.set(tmp)
                ai[i + 1].set(tmp2)
            }

            return ProjectiveNielsPointLookupTable(ai)
        }
    }
}
