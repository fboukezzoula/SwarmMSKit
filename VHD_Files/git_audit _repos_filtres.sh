#!/bin/bash

# ==============================================================================
# SCRIPT D'AUDIT DE NETTOYAGE GITHUB (VERSION CIBLÉE)
# Objectif : Analyser l'état des PRs et branches pour des repos spécifiques.
# ==============================================================================

# --- CONFIGURATION ---
# 1. Configurez votre hôte GitHub Enterprise ici (ex: github.monentreprise.com)
export GH_HOST="github.votre-entreprise.com"

# 2. Fichier contenant la liste des repos à scanner (format: "organisation repo")
SCOPE_FILE="scope.txt"
MAIN_BRANCH="main"
OUTPUT_FILE="audit_report.csv"

# Vérification de l'existence du fichier de scope
if [ ! -f "$SCOPE_FILE" ]; then
    echo "❌ Erreur : Le fichier $SCOPE_FILE est introuvable."
    echo "Veuillez créer un fichier $SCOPE_FILE avec le format : organisation repository"
    exit 1
fi

# Initialisation du fichier de rapport
echo "Organisation,Repository,PR_Number,Branch,Status,Action_Required" > "$OUTPUT_FILE"

echo "🚀 Démarrage de l'audit ciblé... Rapport généré dans $OUTPUT_FILE"

# Lecture du fichier de scope ligne par ligne
while read -r ORG REPO_NAME || [ -n "$ORG" ]; do
    # Ignorer les lignes vides ou les commentaires (commençant par #)
    [[ -z "$ORG" || "$ORG" == \#* ]] && continue

    REPO="$ORG/$REPO_NAME"
    echo "📁 Analyse du repo: $REPO"

    # Cloner le repo dans un dossier temporaire
    TMP_DIR="tmp_$REPO_NAME"
    git clone "https://$GH_HOST/$REPO" "$TMP_DIR" &> /dev/null
    
    if [ $? -ne 0 ]; then
        echo "    ⚠️ Erreur lors du clone de $REPO. Vérifiez vos permissions."
        continue
    fi

    cd "$TMP_DIR" || continue

    # Liste des PRs ouvertes via gh cli
    # Note: On utilise --repo pour être explicite
    PRS=$(gh pr list --repo "$REPO" --state open --json number,headRefName -q '.[] | "\(.number)|\(.headRefName)"')

    if [ -z "$PRS" ]; then
        echo "    - Aucune PR ouverte."
        cd ..
        rm -rf "$TMP_DIR"
        continue
    fi

    for PR_DATA in $PRS; do
        PR_NUM=$(echo "$PR_DATA" | cut -d'|' -f1)
        BRANCH=$(echo "$PR_DATA" | cut -d'|' -f2)
        
        echo "    🔍 Analyse PR #$PR_NUM (branche: $BRANCH)..."

        # S'assurer que main est à jour
        git checkout "$MAIN_BRANCH" &> /dev/null
        git pull origin "$MAIN_BRANCH" &> /dev/null
        
        # Récupérer la branche de la PR
        git fetch origin "$BRANCH" &> /dev/null
        
        # --- ANALYSE ---
        if git merge-base --is-ancestor "origin/$BRANCH" "origin/$MAIN_BRANCH"; then
            STATUS="Already Merged"
            ACTION="Delete Branch"
        else
            MERGE_RESULT=$(git merge-tree "$MAIN_BRANCH" "origin/$BRANCH")
            if echo "$MERGE_RESULT" | grep -q "conflict"; then
                STATUS="Conflict"
                ACTION="Manual Resolve / Rebase"
            else
                if ! git merge-base --is-ancestor "origin/$MAIN_BRANCH" "origin/$BRANCH"; then
                    STATUS="Out of Date"
                    ACTION="Pull --rebase / Merge Main"
                else
                    STATUS="Clean"
                    ACTION="Safe to Merge"
                fi
            fi
        fi

        echo "$ORG,$REPO_NAME,$PR_NUM,$BRANCH,$STATUS,$ACTION" >> "../$OUTPUT_FILE"
    done

    # Nettoyage
    cd ..
    rm -rf "$TMP_DIR"
done < "$SCOPE_FILE"

echo "✅ Audit terminé ! Consultez $OUTPUT_FILE"
