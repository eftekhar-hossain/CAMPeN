import ast


# Overlap Highlighted

def highlight_text_overlap(text, highlighted_sentences):
    # Wrap each highlighted sentence with styled <span> tags
    for x, sentence in enumerate(highlighted_sentences, start=1):  # start=1 for 1-based numbering
        # Badge-styled clause number and bold, yellow sentence
        highlighted_sentence = (
            f"<span class='badge bg-info text-dark'>[Start:{x}]</span> "
            f"<span style='font-weight: italic; background-color: #90EE90;'>{sentence}</span> "
            f"<span class='badge bg-info text-dark'>[End:{x}]</span>"
        )
        # Replace the sentence with the styled version in the text
        text = text.replace(sentence, highlighted_sentence)
    return text


def get_overlap_narratives(narrative1,narrative2, overlap, show_overlap):
    # Extract narrative 1 sentences for highlighting
    overlap_sentences_1 = [item['sentence_1'] for item in overlap] if show_overlap else []
    # Process narrative1 with highlighted sentences
    
    highlighted_narrative1 = highlight_text_overlap(narrative1, overlap_sentences_1 )

    # Extract narrative 2 sentences for highlighting
    overlap_sentences_2 = [item['sentence_2'] for item in overlap] if show_overlap else []
    # Process narrative2 with highlighted sentences
    
    highlighted_narrative2 = highlight_text_overlap(narrative2, overlap_sentences_2)

    highlighted_narratives = [highlighted_narrative1, highlighted_narrative2]

    return highlighted_narratives


# Conflict Highlighted

def highlight_text_conflict(text, highlighted_sentences):
    # Wrap each highlighted sentence with styled <span> tags
    for x, sentence in enumerate(highlighted_sentences, start=1):  # start=1 for 1-based numbering
        # Badge-styled clause number and bold, yellow sentence
        highlighted_sentence = (
            f"<span class='badge bg-info text-dark'>[Start:{x}]</span> "
            f"<span style='font-weight: italic; background-color: #FFADB0;'>{sentence}</span> "
            f"<span class='badge bg-info text-dark'>[End:{x}]</span>"
        )
        # Replace the sentence with the styled version in the text
        text = text.replace(sentence, highlighted_sentence)
    return text


def get_conflict_narratives(narrative1,narrative2, conflict, show_conflict):
    # Extract narrative 1 sentences for highlighting
    conflict_sentences_1 = [item['sentence_1'] for item in conflict] if show_conflict else []
    # print(conflict_sentences_1)
    # Process narrative1 with highlighted sentences
    
    highlighted_narrative1 = highlight_text_conflict(narrative1, conflict_sentences_1 )
    # print(highlighted_narrative1)

    # Extract narrative 2 sentences for highlighting
    conflict_sentences_2 = [item['sentence_2'] for item in conflict] if show_conflict else []
    # Process narrative2 with highlighted sentences
    
    highlighted_narrative2 = highlight_text_conflict(narrative2, conflict_sentences_2)

    highlighted_narratives_conflict = [highlighted_narrative1, highlighted_narrative2]
    # print(highlighted_narratives)

    return highlighted_narratives_conflict


# Unique Highlights

def highlight_text_unique(text, highlighted_sentences):
    # Wrap each highlighted sentence with styled <span> tags
    for x, sentence in enumerate(highlighted_sentences, start=1):  # start=1 for 1-based numbering
        # Badge-styled clause number and bold, yellow sentence
        highlighted_sentence = (
            f"<span class='badge bg-info text-dark'>[Start:{x}]</span> "
            f"<span style='font-weight: italic; background-color: #ffce1b;'>{sentence}</span> "
            f"<span class='badge bg-info text-dark'>[End:{x}]</span>"
        )
        # Replace the sentence with the styled version in the text
        text = text.replace(sentence, highlighted_sentence)
    return text

def get_unique_narratives(narrative1, narrative2, unique1, 
                          unique2, show_unique1, show_unique2):
    # Extract narrative 1 sentences for highlighting
    unique1_sentences = [item['sentence_1'] for item in unique1] if show_unique1 else []
    # print(conflict_sentences_1)
    # Process narrative1 with highlighted sentences
    
    highlighted_narrative1 = highlight_text_unique(narrative1, unique1_sentences )
    # print(highlighted_narrative1)

    # Extract narrative 2 sentences for highlighting
    unique2_sentences = [item['sentence_2'] for item in unique2] if show_unique2 else []
    # Process narrative2 with highlighted sentences
    highlighted_narrative2 = highlight_text_unique(narrative2, unique2_sentences)

    highlighted_narratives_unique = [highlighted_narrative1, highlighted_narrative2]

    return highlighted_narratives_unique