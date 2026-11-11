package com.trust.security.web;

/**
 * Conservative overlap check between two request patterns, used by the
 * startup validations of both Trust security starters (multi-chain scopes,
 * tenant login path). Kept here, in the one module both starters depend on,
 * so the two starters always reach the same verdict.
 * <p>
 * Two patterns overlap when one is a prefix of the other, segment by
 * segment: {@code /app/**}, {@code /app} and {@code /app/admin} all overlap,
 * {@code /**} overlaps everything. A segment containing {@code *}, {@code ?}
 * or a {@code {variable}} may match any value, so {@code /{tenant}/login}
 * overlaps {@code /acme/**}. A {@code **} anywhere overlaps from that point.
 * When in doubt it reports an overlap: a false positive fails startup
 * loudly, a false negative would let two configurations silently compete.
 */
public final class RequestPatterns {

    private RequestPatterns() {
    }

    public static boolean overlap(String a, String b) {
        String[] segmentsA = segments(a);
        String[] segmentsB = segments(b);
        int common = Math.min(segmentsA.length, segmentsB.length);

        for (int i = 0; i < common; i++) {
            String segmentA = segmentsA[i];
            String segmentB = segmentsB[i];
            if (segmentA.equals("**") || segmentB.equals("**")) {
                return true;
            }
            if (!isWildcard(segmentA) && !isWildcard(segmentB) && !segmentA.equals(segmentB)) {
                return false;
            }
        }
        return true;
    }

    private static String[] segments(String pattern) {
        String trimmed = pattern.strip();
        while (trimmed.startsWith("/")) {
            trimmed = trimmed.substring(1);
        }
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed.isEmpty() ? new String[0] : trimmed.split("/+");
    }

    private static boolean isWildcard(String segment) {
        return segment.contains("*") || segment.contains("?") || segment.contains("{");
    }
}
