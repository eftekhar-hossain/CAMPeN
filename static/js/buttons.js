document.addEventListener('DOMContentLoaded', function() {
    // Function to handle response button click
    function handleResponseButtonClick(event) {
        const button = event.currentTarget;
        const clauseId = button.getAttribute('data-clause-id');
        const clauseType = button.getAttribute('data-clause-type');
        const choice = button.getAttribute('data-choice');

        // Prepare data to send to the server
        const data = {
            'clause_id': clauseId,
            'clause_type': clauseType,
            'choice': choice
        };

        // Retrieve the CSRF token
        const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

        // Send the data to the server using fetch
        fetch('/record_response', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify(data)
        })
        .then(response => response.json())
        .then(result => {
            const parentDiv = button.parentElement;
            const buttons = parentDiv.querySelectorAll('.response-button');

            // Disable all response buttons and remove active class
            buttons.forEach(btn => {
                btn.disabled = true;
                btn.classList.remove('selected-response');
            });

            // Add 'selected-response' class to the clicked button for visual feedback
            button.classList.add('selected-response');

            // Remove existing redo button if any
            let existingRedo = parentDiv.querySelector('.redo-button');
            if (existingRedo) {
                existingRedo.remove();
            }

            // Create and insert the "Redo" button on the left side
            const redoButton = document.createElement('button');
            redoButton.textContent = 'Redo';
            redoButton.className = 'btn btn-warning btn-sm me-2 redo-button';

            // Insert the "Redo" button before the response buttons
            parentDiv.insertBefore(redoButton, parentDiv.firstChild);

            // Add event listener to "Redo" button
            redoButton.addEventListener('click', function() {
                // Re-enable all response buttons
                buttons.forEach(btn => btn.disabled = false);

                // Remove visual feedback from previously selected button
                buttons.forEach(btn => btn.classList.remove('selected-response'));

                // Remove the "Redo" button
                redoButton.remove();

                // Prepare data to send to the server
                const deleteData = {
                    'clause_id': clauseId,
                    'clause_type': clauseType
                };

                // Send a DELETE request to the server to remove the existing response
                fetch('/delete_response', {
                    method: 'DELETE',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken
                    },
                    body: JSON.stringify(deleteData)
                })
                .then(response => response.json())
                .then(result => {
                    console.log('Response deleted from database');
                })
                .catch(error => {
                    console.error('Error:', error);
                });
            });
        })
        .catch(error => {
            console.error('Error:', error);
        });
    }

    // Attach event listeners to all response buttons
    document.querySelectorAll('.response-button').forEach(button => {
        button.addEventListener('click', handleResponseButtonClick);
    });

    // Pre-select saved responses and add redo buttons
    const savedResponses = JSON.parse(document.getElementById('saved-responses').textContent);
    for (const key in savedResponses) {
        const [clauseId, clauseType] = key.split('_');
        const choice = savedResponses[key];
        const button = document.querySelector(`.response-button[data-clause-id="${clauseId}"][data-clause-type="${clauseType}"][data-choice="${choice}"]`);

        if (button) {
            const parentDiv = button.parentElement;
            const buttons = parentDiv.querySelectorAll('.response-button');

            // Disable all buttons and highlight the selected one
            buttons.forEach(btn => btn.disabled = true);
            button.classList.add('selected-response');

            // Create and insert the "Redo" button
            const redoButton = document.createElement('button');
            redoButton.textContent = 'Redo';
            redoButton.className = 'btn btn-warning btn-sm me-2 redo-button';
            parentDiv.insertBefore(redoButton, parentDiv.firstChild);

            // Add event listener to "Redo" button
            redoButton.addEventListener('click', function() {
                buttons.forEach(btn => btn.disabled = false);
                buttons.forEach(btn => btn.classList.remove('selected-response'));
                redoButton.remove();
            });
        }
    }
});