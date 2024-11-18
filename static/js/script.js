// Escape special regex characters
function escapeSpecialChar(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Normalize whitespace
function normalizeWhitespace(string) {
    return string.replace(/\s+/g, ' ').trim();
}

// Decode HTML entities
function decodeHTMLEntities(text) {
    var txt = document.createElement("textarea");
    txt.innerHTML = text;
    return txt.value;
}

function highlightClause(sentence1, sentence2, buttonId, clauseNumber) {
    const narrative1 = document.getElementById('narrative1');
    const narrative2 = document.getElementById('narrative2');
    const button = document.getElementById(buttonId);

    // Define Start and End tokens with unique clauseNumber
    const startToken = `<span class="badge bg-info text-dark">[Start:${clauseNumber}]</span> `;
    const endToken = ` <span class="badge bg-info text-dark">[End:${clauseNumber}]</span>`;

    // Escape special characters
    const escapedSentence1 = escapeSpecialChar(sentence1); 
    const escapedSentence2 = escapeSpecialChar(sentence2);
    const escapedStartToken = escapeSpecialChar(startToken);
    const escapedEndToken = escapeSpecialChar(endToken);

    // Decode and normalize narratives
    const decodedNarrative1 = decodeHTMLEntities(narrative1.innerHTML);
    const decodedNarrative2 = decodeHTMLEntities(narrative2.innerHTML);
    const normalizedNarrative1 = normalizeWhitespace(decodedNarrative1);
    const normalizedNarrative2 = normalizeWhitespace(decodedNarrative2);

    // Normalize sentences
    const normalizedSentence1 = normalizeWhitespace(sentence1);
    const normalizedSentence2 = normalizeWhitespace(sentence2);

    // Convert to lower case for case-insensitive comparison
    const lowerNarrative1 = normalizedNarrative1.toLowerCase();
    const lowerNarrative2 = normalizedNarrative2.toLowerCase();
    const lowerSentence1 = normalizedSentence1.toLowerCase();
    const lowerSentence2 = normalizedSentence2.toLowerCase();

    // Define normalized startToken for searching
    const normalizedStartToken = normalizeWhitespace(startToken).toLowerCase();

    // Check if the specific clause is currently highlighted in narratives
    const isHighlighted1 = lowerNarrative1.includes(normalizedStartToken);
    const isHighlighted2 = lowerNarrative2.includes(normalizedStartToken);

    // Initialize flags to track highlighting success
    let highlightFailed1 = false;
    let highlightFailed2 = false;

    if (isHighlighted1 || isHighlighted2) {
        // Remove the specific clause's highlight and tokens by replacing them with original
        if (isHighlighted1) {
            // Construct regex to match the exact highlighted clause in narrative1
            const regex1 = new RegExp(
                escapedStartToken + 
                '<span class="highlight-overlap">' + 
                escapedSentence1 + 
                '</span>' + 
                escapedEndToken, 
                'gi'
            );
            narrative1.innerHTML = narrative1.innerHTML.replace(regex1, sentence1);
        }
        if (isHighlighted2) {
            // Construct regex to match the exact highlighted clause in narrative2
            const regex2 = new RegExp(
                escapedStartToken + 
                '<span class="highlight-overlap">' + 
                escapedSentence2 + 
                '</span>' + 
                escapedEndToken, 
                'gi'
            );
            narrative2.innerHTML = narrative2.innerHTML.replace(regex2, sentence2);
        }

        // Update button state
        button.classList.remove('active');
        button.innerText = 'Highlight';
    } 
    else {
        // Add highlight with start and end tokens
        let highlighted = false;

        // Attempt to highlight in Narrative 1
        if (lowerNarrative1.includes(lowerSentence1)) {
            narrative1.innerHTML = narrative1.innerHTML.replace(new RegExp(escapedSentence1, 'gi'), function(matched) {
                return `${startToken}<span class="highlight-overlap">${matched}</span>${endToken}`;
            });
            highlighted = true;

            // Verify if highlighting was successful for Narrative 1
            const updatedNarrative1 = decodeHTMLEntities(narrative1.innerHTML);
            const normalizedUpdatedNarrative1 = normalizeWhitespace(updatedNarrative1).toLowerCase();
            const clausePattern1 = normalizeWhitespace(startToken).toLowerCase();
            if (!normalizedUpdatedNarrative1.includes(clausePattern1)) {
                highlightFailed1 = true;
            }
        } else {
            highlightFailed1 = true;
        }

        // Attempt to highlight in Narrative 2
        if (lowerNarrative2.includes(lowerSentence2)) {
            narrative2.innerHTML = narrative2.innerHTML.replace(new RegExp(escapedSentence2, 'gi'), function(matched) {
                return `${startToken}<span class="highlight-overlap">${matched}</span>${endToken}`;
            });
            highlighted = true;

            // Verify if highlighting was successful for Narrative 2
            const updatedNarrative2 = decodeHTMLEntities(narrative2.innerHTML);
            const normalizedUpdatedNarrative2 = normalizeWhitespace(updatedNarrative2).toLowerCase();
            const clausePattern2 = normalizeWhitespace(startToken).toLowerCase();
            if (!normalizedUpdatedNarrative2.includes(clausePattern2)) {
                highlightFailed2 = true;
            }
        } else {
            highlightFailed2 = true;
        }

        // Update button state and handle error messages
        if (highlighted) {
            button.classList.add('active');
            button.innerText = 'Hide';
            window.scrollTo({top: 0, behavior: 'smooth'});
        }

        // Prepare error messages based on which highlights failed
        let errorMessage = "";
        if (highlightFailed1 && highlightFailed2) {
            errorMessage = "Exact match not found in both Document 1 and Document 2; you must check the documents.";
        } else if (highlightFailed1) {
            errorMessage = "Exact match not found in Document 1; you must check the document.";
        } else if (highlightFailed2) {
            errorMessage = "Exact match not found in Document 2; you must check the document.";
        }

        if (errorMessage) {
            alert(errorMessage);
        }
    }
}

function highlightUnique1(sentence1, buttonId, clauseNumber) {
    const narrative1 = document.getElementById('narrative1');
    const button = document.getElementById(buttonId);

    // Define Start and End tokens with unique clauseNumber
    const startToken = `<span class="badge bg-info text-dark">[Start:${clauseNumber}]</span> `;
    const endToken = ` <span class="badge bg-info text-dark">[End:${clauseNumber}]</span>`;

    // Escape special characters 
    const escapedSentence1 = escapeSpecialChar(sentence1); 
    const escapedStartToken = escapeSpecialChar(startToken);
    const escapedEndToken = escapeSpecialChar(endToken);

    // Decode and normalize narrative
    const decodedNarrative1 = decodeHTMLEntities(narrative1.innerHTML);
    const normalizedNarrative1 = normalizeWhitespace(decodedNarrative1);

    // Normalize sentence
    const normalizedSentence1 = normalizeWhitespace(sentence1);

    // Convert to lower case for case-insensitive comparison
    const lowerNarrative1 = normalizedNarrative1.toLowerCase();
    const lowerSentence1 = normalizedSentence1.toLowerCase();

    // Define normalized startToken for searching
    const normalizedStartToken = normalizeWhitespace(startToken).toLowerCase();

    // Check if the specific clause is currently highlighted
    const isHighlighted1 = lowerNarrative1.includes(normalizedStartToken);

    // Initialize flag to track highlighting success
    let highlightFailed1 = false;

    if (isHighlighted1) {
        // Remove the specific clause's highlight and tokens by replacing them with original
        // Construct regex to match the exact highlighted clause in narrative1
        const regex1 = new RegExp(
            escapedStartToken + 
            '<span class="highlight-overlap">' + 
            escapedSentence1 + 
            '</span>' + 
            escapedEndToken, 
            'gi'
        );
        narrative1.innerHTML = narrative1.innerHTML.replace(regex1, sentence1);

        // Update button state
        button.classList.remove('active');
        button.innerText = 'Highlight';
    } 
    else {
        // Add highlight with start and end tokens
        if (lowerNarrative1.includes(lowerSentence1)) {
            narrative1.innerHTML = narrative1.innerHTML.replace(new RegExp(escapedSentence1, 'gi'), function(matched) {
                return `${startToken}<span class="highlight-overlap">${matched}</span>${endToken}`;
            });

            // Verify if highlighting was successful
            const updatedNarrative1 = decodeHTMLEntities(narrative1.innerHTML);
            const normalizedUpdatedNarrative1 = normalizeWhitespace(updatedNarrative1).toLowerCase();
            const clausePattern1 = normalizeWhitespace(startToken).toLowerCase();
            if (!normalizedUpdatedNarrative1.includes(clausePattern1)) {
                highlightFailed1 = true;
            } else {
                // Update button state
                button.classList.add('active');
                button.innerText = 'Hide';
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        } else {
            highlightFailed1 = true;
        }

        // Handle error message
        if (highlightFailed1) {
            alert("Exact match not found in Document 1; you must check the document.");
        }
    }
}

function highlightUnique2(sentence2, buttonId, clauseNumber) {
    const narrative2 = document.getElementById('narrative2');
    const button = document.getElementById(buttonId);

    // Define Start and End tokens with unique clauseNumber
    const startToken = `<span class="badge bg-info text-dark">[Start:${clauseNumber}]</span> `;
    const endToken = ` <span class="badge bg-info text-dark">[End:${clauseNumber}]</span>`;

    // Escape special characters
    const escapedSentence2 = escapeSpecialChar(sentence2); 
    const escapedStartToken = escapeSpecialChar(startToken);
    const escapedEndToken = escapeSpecialChar(endToken);

    // Decode and normalize narrative
    const decodedNarrative2 = decodeHTMLEntities(narrative2.innerHTML);
    const normalizedNarrative2 = normalizeWhitespace(decodedNarrative2);

    // Normalize sentence
    const normalizedSentence2 = normalizeWhitespace(sentence2);

    // Convert to lower case for case-insensitive comparison
    const lowerNarrative2 = normalizedNarrative2.toLowerCase();
    const lowerSentence2 = normalizedSentence2.toLowerCase();

    // Define normalized startToken for searching
    const normalizedStartToken = normalizeWhitespace(startToken).toLowerCase();

    // Check if the specific clause is currently highlighted
    const isHighlighted2 = lowerNarrative2.includes(normalizedStartToken);

    // Initialize flag to track highlighting success
    let highlightFailed2 = false;

    if (isHighlighted2) {
        // Remove the specific clause's highlight and tokens by replacing them with original
        // Construct regex to match the exact highlighted clause in narrative2
        const regex2 = new RegExp(
            escapedStartToken + 
            '<span class="highlight-overlap">' + 
            escapedSentence2 + 
            '</span>' + 
            escapedEndToken, 
            'gi'
        );
        narrative2.innerHTML = narrative2.innerHTML.replace(regex2, sentence2);

        // Update button state
        button.classList.remove('active');
        button.innerText = 'Highlight';
    } 
    else {
        // Add highlight with start and end tokens
        if (lowerNarrative2.includes(lowerSentence2)) {
            narrative2.innerHTML = narrative2.innerHTML.replace(new RegExp(escapedSentence2, 'gi'), function(matched) {
                return `${startToken}<span class="highlight-overlap">${matched}</span>${endToken}`;
            });

            // Verify if highlighting was successful
            const updatedNarrative2 = decodeHTMLEntities(narrative2.innerHTML);
            const normalizedUpdatedNarrative2 = normalizeWhitespace(updatedNarrative2).toLowerCase();
            const clausePattern2 = normalizeWhitespace(startToken).toLowerCase();
            if (!normalizedUpdatedNarrative2.includes(clausePattern2)) {
                highlightFailed2 = true;
            } else {
                // Update button state
                button.classList.add('active');
                button.innerText = 'Hide';
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        } else {
            highlightFailed2 = true;
        }

        // Handle error message
        if (highlightFailed2) {
            alert("Exact match not found in Document 2; you must check the document.");
        }
    }
}

// Event Listener for Scrolling Based on URL Parameters
document.addEventListener("DOMContentLoaded", function() {
    const urlParams = new URLSearchParams(window.location.search);
    const action = urlParams.get("action");

    if (action === "showOverlap") { 
        const overlapSection = document.getElementById("overlapSection");
        if (overlapSection) {
            overlapSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }
    else if (action === "showConflict") { // Updated to "showConflict" for conflict section
        const conflictSection = document.getElementById("conflictSection");
        if (conflictSection) {
            conflictSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    } 
    else if (action === "showUnique1") { // Corrected comment to match the action
        const unique1Section = document.getElementById("unique1Section");
        if (unique1Section) {
            unique1Section.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }
    else if (action === "showUnique2") { // Corrected comment to match the action
        const unique2Section = document.getElementById("unique2Section");
        if (unique2Section) {
            unique2Section.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }

    else if (action === "hide") {
        const narrativeBox = document.getElementById("narrativeBox");
        if (narrativeBox) {
            narrativeBox.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    }
});
